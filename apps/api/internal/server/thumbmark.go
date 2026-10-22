package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"nazr/api/internal/auth"
	"nazr/api/internal/classify"
	"nazr/api/internal/config"
	"nazr/api/internal/conn"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/h2fp"
	"nazr/api/internal/httpfp"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/tlsfp"
	"nazr/api/internal/visitor"
)

const (
	maxMetadataChars = 1000
	storeTimeout     = 5 * time.Second
)

// thumbmarkBody is the decoded /thumbmark request (spec section 4.1).
type thumbmarkBody struct {
	components  map[string]any
	options     map[string]any
	clientHash  string
	version     string
	path        string
	visitorID   string
	metadata    any // nil when absent, null, or over the size cap
	metadataRaw json.RawMessage
}

type ipAddressInfo struct {
	IPAddress    string `json:"ip_address"`
	IPIdentifier string `json:"ip_identifier"`
	ASN          uint32 `json:"autonomous_system_number"`
	IPVersion    string `json:"ip_version"`
}

type classificationInfo struct {
	Tor          bool `json:"tor"`
	VPN          bool `json:"vpn"`
	Bot          bool `json:"bot"`
	Datacenter   bool `json:"datacenter"`
	PrivateRelay bool `json:"private_relay"`
	DangerLevel  int  `json:"danger_level"`
}

type uniquenessInfo struct {
	Score           float64 `json:"score"`
	VisitorsSharing int64   `json:"visitors_sharing"`
	VisitorsTotal   int64   `json:"visitors_total"`
}

type continentInfo struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type countryInfo struct {
	ISOCode   string        `json:"iso_code"`
	Name      string        `json:"name"`
	Continent continentInfo `json:"continent"`
}

type visitorInfo struct {
	ID        string `json:"id"`
	IsNew     bool   `json:"isNew"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
}

type infoBlock struct {
	IPAddress      *ipAddressInfo     `json:"ip_address,omitempty"`
	Classification classificationInfo `json:"classification"`
	Uniqueness     uniquenessInfo     `json:"uniqueness"`
	Country        *countryInfo       `json:"country,omitempty"`
	Visitor        visitorInfo        `json:"visitor"`
	Signals        map[string]bool    `json:"signals"`
}

type collectDirective struct {
	JA4    string `json:"ja4"`
	Source string `json:"source"`
}

type thumbmarkResponse struct {
	Thumbmark  string            `json:"thumbmark"`
	Components map[string]any    `json:"components"`
	Info       infoBlock         `json:"info"`
	VisitorID  string            `json:"visitorId"`
	RequestID  string            `json:"requestId"`
	Version    string            `json:"version"`
	Metadata   any               `json:"metadata,omitempty"`
	Collect    *collectDirective `json:"collect,omitempty"`
}

// bodyLimit caps the request body at NAZR_BODY_LIMIT.
func (s *server) bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.Cfg.BodyLimit))
		next.ServeHTTP(w, r)
	})
}

// acceptableContentType allows application/json, text/plain (simple_request
// mode) and a missing Content-Type.
func acceptableContentType(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || mt == "text/plain")
}

func isTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe) || errors.Is(err, fingerprint.ErrTooLarge)
}

func parseThumbmarkBody(raw map[string]any) (thumbmarkBody, error) {
	var b thumbmarkBody
	comps, ok := raw["components"].(map[string]any)
	if !ok {
		return b, errors.New(`"components" must be an object`)
	}
	b.components = comps
	b.options, _ = raw["options"].(map[string]any)
	b.clientHash, _ = raw["clientHash"].(string)
	b.version, _ = raw["version"].(string)
	b.path, _ = raw["path"].(string)
	b.visitorID, _ = raw["visitorId"].(string)
	if md, present := raw["metadata"]; present && md != nil {
		enc, err := marshalJSON(md)
		size := 0
		if str, isStr := md.(string); isStr {
			size = len(utf16.Encode([]rune(str)))
		} else if err == nil {
			size = len(utf16.Encode([]rune(string(enc))))
		}
		if err == nil && size <= maxMetadataChars {
			b.metadata, b.metadataRaw = md, enc
		}
	}
	return b, nil
}

// marshalJSON encodes like JSON.stringify (no HTML escaping, no newline).
func marshalJSON(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// serverComponents builds the server-observed components (unfiltered) and
// returns the JA4 in effect ("" when none). order is the request's own wire
// header order (nil: httpfp falls back to sorted keys). Every value is a type
// fingerprint.StableStringify accepts.
func serverComponents(r *http.Request, view conn.HolderView, order []string, cfg config.Config, addr netip.Addr, lookup ipintel.Lookup) (map[string]any, string) {
	sc := map[string]any{}
	ja4 := ""
	tr := view.TLS
	if tr == nil {
		if v := proxiedJA4(r, cfg); v != "" {
			tr = &tlsfp.Result{JA4: v} // synthetic: only the proxy's JA4 is known
		}
	}
	if tr != nil {
		if tr.Hello != nil {
			sc["tls"] = tr.Component()
		} else {
			sc["tls"] = map[string]any{"ja4": tr.JA4}
		}
		ja4 = tr.JA4
	}
	if view.H2 != nil {
		sc["h2"] = view.H2.Component()
	}
	sc["header"] = httpfp.Component(r, order)
	if addr.IsValid() {
		sc["ip"] = ipintel.Component(addr, lookup)
	}
	return sc, ja4
}

// proxiedJA4 returns the proxy-supplied JA4 header in proxied mode.
func proxiedJA4(r *http.Request, cfg config.Config) string {
	if cfg.TLSMode != "proxied" || cfg.JA4Header == "" {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(cfg.JA4Header))
}

// filterServer filters the server components with the client's rules. The
// stabilization rules depend on the browser, which only the client components
// carry (components.system.browser), so it is lent to Filter and removed
// again; this mirrors the client's filterThumbmarkData over the API
// components, where getBrowser() supplies the same browser.
func filterServer(server, client map[string]any, opts fingerprint.Options) map[string]any {
	sys, ok := client["system"]
	if !ok {
		return fingerprint.Filter(server, opts)
	}
	in := make(map[string]any, len(server)+1)
	for k, v := range server {
		in[k] = v
	}
	in["system"] = sys
	out := fingerprint.Filter(in, opts)
	delete(out, "system") // the server never emits a "system" component
	return out
}

func (s *server) ja4Families(ctx context.Context, ja4 string) []string {
	if ja4 == "" {
		return nil
	}
	var fams []string
	if s.Intel != nil {
		fams = append(fams, s.Intel.JA4Families(ja4)...)
	}
	local, err := s.Store.UAJA4Families(ctx, ja4, s.Cfg.UAJA4MinObservations)
	if err != nil {
		s.Logger.Warn("server: ua/ja4 observations lookup failed", "err", err)
	}
	fams = append(fams, local...)
	slices.Sort(fams)
	return slices.Compact(fams)
}

func (s *server) handleThumbmark(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := auth.KeyFromContext(ctx)
	if key == nil {
		writeError(w, http.StatusForbidden, "unauthorized", "missing API key")
		return
	}
	if !acceptableContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadRequest, codeBadRequest, "Content-Type must be application/json or text/plain")
		return
	}
	raw, err := fingerprint.Decode(r.Body, int64(s.Cfg.BodyLimit))
	if err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body exceeds "+strconv.Itoa(s.Cfg.BodyLimit)+" bytes")
			return
		}
		writeError(w, http.StatusBadRequest, codeBadRequest, "body must be a JSON object")
		return
	}
	body, err := parseThumbmarkBody(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
		return
	}
	if err := s.Store.Ping(ctx); err != nil {
		s.Logger.Error("server: store ping failed", "err", err, "request_id", requestIDFrom(ctx))
		storeUnavailable(w, "store unavailable")
		return
	}

	addr, view := s.clientIP(r)
	s.countParseErrors(ctx, view)
	var lookup ipintel.Lookup
	if s.Intel != nil && addr.IsValid() {
		lookup = s.Intel.Lookup(addr)
	}
	order := requestOrder(r)
	sc, ja4 := serverComponents(r, view, order, s.Cfg, addr, lookup)
	hasTLS := view.TLS != nil || ja4 != ""

	opts := fingerprint.OptionsFromRequest(body.options)
	merged := fingerprint.Merge(body.components, filterServer(sc, body.components, opts))
	thumbmark := fingerprint.Hash(merged)

	in := classify.Input{
		IP:                    lookup,
		HasTLS:                hasTLS,
		UserAgent:             r.Header.Get("User-Agent"),
		AcceptLanguagePresent: r.Header.Get("Accept-Language") != "",
		JA4Families:           s.ja4Families(ctx, ja4),
	}
	if loc, ok := body.components["locales"].(map[string]any); ok {
		in.Timezone, _ = loc["timezone"].(string)
	}
	if priv, ok := body.components["privacy"].(map[string]any); ok {
		in.Webdriver, _ = priv["webdriver"].(bool)
	}
	h2fpStr := ""
	if view.H2 != nil {
		h2fpStr = h2fp.Akamai(view.H2)
		in.H2Fingerprint = h2fpStr
	}
	cls := classify.Classify(in)
	classificationTotal.WithLabelValues(strconv.FormatBool(cls.Tor), strconv.FormatBool(cls.VPN),
		strconv.FormatBool(cls.Bot), strconv.FormatBool(cls.Datacenter), strconv.FormatBool(cls.PrivateRelay)).Inc()

	vis, err := s.Resolver.Resolve(ctx, key.ID, body.visitorID, thumbmark)
	if err != nil {
		s.Logger.Error("server: visitor resolution failed", "err", err, "request_id", requestIDFrom(ctx))
		storeUnavailable(w, "store unavailable")
		return
	}

	rid := requestIDFrom(ctx)
	ipHash := ""
	resp := thumbmarkResponse{
		Thumbmark:  thumbmark,
		Components: sc,
		Info: infoBlock{
			Classification: classificationInfo{Tor: cls.Tor, VPN: cls.VPN, Bot: cls.Bot,
				Datacenter: cls.Datacenter, PrivateRelay: cls.PrivateRelay, DangerLevel: cls.DangerLevel},
			Uniqueness: uniquenessInfo{Score: visitor.Uniqueness(vis.Sharing, vis.Total),
				VisitorsSharing: vis.Sharing, VisitorsTotal: vis.Total},
			Visitor: visitorInfo{ID: vis.ID, IsNew: vis.IsNew,
				FirstSeen: vis.FirstSeen.UTC().Format(time.RFC3339), LastSeen: vis.LastSeen.UTC().Format(time.RFC3339)},
			Signals: cls.Signals,
		},
		VisitorID: vis.ID,
		RequestID: rid,
		Version:   s.Version,
		Metadata:  body.metadata,
	}
	if addr.IsValid() {
		ipHash = ipintel.Identifier(addr, s.Cfg.IPHashSalt)
		ver := "v6"
		if addr.Is4() {
			ver = "v4"
		}
		resp.Info.IPAddress = &ipAddressInfo{IPAddress: addr.String(), IPIdentifier: ipHash, ASN: lookup.ASN, IPVersion: ver}
	}
	if lookup.Country != "" {
		resp.Info.Country = &countryInfo{ISOCode: lookup.Country, Name: lookup.CountryName,
			Continent: continentInfo{Code: lookup.ContinentCode, Name: lookup.ContinentName}}
	}
	if !hasTLS && s.Rand() < s.Cfg.CollectSampleRate {
		// No JA4 was observed for this request (that is why it is sampled),
		// so there is nothing to report: source "none". "header" would name
		// the proxy header a JA4 came from, but then collect is not sent.
		resp.Collect = &collectDirective{JA4: "", Source: "none"}
	}

	ev := store.Event{
		ID: rid, APIKeyID: key.ID, VisitorID: vis.ID, Thumbmark: thumbmark, ClientHash: body.clientHash,
		IPHash: ipHash, JA4: ja4, H2FP: h2fpStr, UserAgent: in.UserAgent, Path: body.path,
		// The component (and so the hash) uses the cookie-free ja4h; the
		// event keeps the complete fingerprint for analysis.
		JA4H:     httpfp.JA4HFull(r, order),
		Metadata: body.metadataRaw, CreatedAt: s.Now().UTC(),
	}
	// JA3 is event-only (not a component): it hashes the extension wire
	// order, which Chromium permutes per connection.
	if view.TLS != nil {
		ev.JA3Hash = view.TLS.JA3Hash
	}
	if s.Cfg.StoreIP == "raw" && addr.IsValid() {
		a := addr
		ev.IP = &a
	}
	ev.Classification, _ = marshalJSON(resp.Info.Classification)
	ev.Signals, _ = marshalJSON(cls.Signals)
	if s.Cfg.StoreComponents {
		if b, err := marshalJSON(fingerprint.Merge(body.components, sc)); err == nil {
			ev.Components = b
		}
	}
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	if err := s.Store.InsertEvent(ictx, ev); err != nil {
		s.Logger.Error("server: insert event failed", "err", err, "request_id", rid)
	}
	cancel()

	writeJSON(w, http.StatusOK, resp)
}

func (s *server) countParseErrors(ctx context.Context, view conn.HolderView) {
	if view.TLSError != nil {
		parseErrorsTotal.WithLabelValues("tls").Inc()
		s.Logger.Warn("server: tls fingerprint unavailable", "err", view.TLSError, "request_id", requestIDFrom(ctx))
	}
	if view.H2Error != nil {
		parseErrorsTotal.WithLabelValues("h2").Inc()
		s.Logger.Warn("server: h2 fingerprint unavailable", "err", view.H2Error, "request_id", requestIDFrom(ctx))
	}
}
