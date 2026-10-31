// Package config loads nazr configuration from NAZR_* environment variables.
package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const redacted = "<redacted>"

// Config is the typed nazr configuration. Each field's `env` tag is the full
// environment variable name; `secret:"true"` fields are hidden by Redacted.
type Config struct {
	// Core.
	DatabaseURL        string   `env:"NAZR_DATABASE_URL" secret:"true"`
	RedisURL           string   `env:"NAZR_REDIS_URL" secret:"true"`
	ListenAddr         string   `env:"NAZR_LISTEN_ADDR" envDefault:":443"`
	HTTPAddr           string   `env:"NAZR_HTTP_ADDR" envDefault:":80"`               // "off" disables
	MetricsAddr        string   `env:"NAZR_METRICS_ADDR" envDefault:"127.0.0.1:9090"` // "off" disables
	TLSMode            string   `env:"NAZR_TLS_MODE" envDefault:"terminate"`
	TLSCertPEM         string   `env:"NAZR_TLS_CERT_PEM"`
	TLSKeyPEM          string   `env:"NAZR_TLS_KEY_PEM" secret:"true"`
	TLSCertFile        string   `env:"NAZR_TLS_CERT_FILE"`
	TLSKeyFile         string   `env:"NAZR_TLS_KEY_FILE"`
	ACMEDomains        []string `env:"NAZR_ACME_DOMAINS"`
	ACMEEmail          string   `env:"NAZR_ACME_EMAIL"`
	ACMEDir            string   `env:"NAZR_ACME_DIR"`
	ProxyProtocol      bool     `env:"NAZR_PROXY_PROTOCOL"`
	TrustedProxies     []string `env:"NAZR_TRUSTED_PROXIES"`
	ClientIPHeader     string   `env:"NAZR_CLIENT_IP_HEADER" envDefault:"x-forwarded-for"`
	JA4Header          string   `env:"NAZR_JA4_HEADER" envDefault:"x-ja4"`
	CORSOrigins        []string `env:"NAZR_CORS_ORIGINS" envDefault:"*"`
	AdminToken         string   `env:"NAZR_ADMIN_TOKEN" secret:"true"`
	DefaultRateLimit   int      `env:"NAZR_DEFAULT_RATE_LIMIT" envDefault:"600"`
	BodyLimit          int      `env:"NAZR_BODY_LIMIT" envDefault:"262144"`
	DataDir            string   `env:"NAZR_DATA_DIR" envDefault:"/data"`
	DemoDir            string   `env:"NAZR_DEMO_DIR"`
	WidgetDir          string   `env:"NAZR_WIDGET_DIR"` // empty: the embedded widget
	AutoMigrate        bool     `env:"NAZR_AUTO_MIGRATE" envDefault:"true"`
	CanvasProbeScoring bool     `env:"NAZR_CANVAS_PROBE_SCORING" envDefault:"false"`
	LogLevel           string   `env:"NAZR_LOG_LEVEL" envDefault:"info"`
	LogFormat          string   `env:"NAZR_LOG_FORMAT" envDefault:"json"`

	// Intel.
	MaxMindAccountID     string   `env:"NAZR_MAXMIND_ACCOUNT_ID"`
	MaxMindLicenseKey    string   `env:"NAZR_MAXMIND_LICENSE_KEY" secret:"true"`
	MaxMindEditions      []string `env:"NAZR_MAXMIND_EDITIONS" envDefault:"GeoLite2-City,GeoLite2-ASN"`
	AppleRelayURL        string   `env:"NAZR_APPLE_RELAY_URL"`
	TorExitURL           string   `env:"NAZR_TOR_EXIT_URL"`
	DatacenterURLs       []string `env:"NAZR_DATACENTER_URLS"`
	VPNURLs              []string `env:"NAZR_VPN_URLS"`
	JA4DBURL             string   `env:"NAZR_JA4DB_URL"`
	JA4DBToken           string   `env:"NAZR_JA4DB_TOKEN" secret:"true"`
	ListsDisable         []string `env:"NAZR_LISTS_DISABLE"`
	UAJA4MinObservations int      `env:"NAZR_UA_JA4_MIN_OBSERVATIONS" envDefault:"20"`
	CollectSampleRate    float64  `env:"NAZR_COLLECT_SAMPLE_RATE" envDefault:"0.01"`

	// Identity and storage.
	VisitorMatchWindow time.Duration `env:"NAZR_VISITOR_MATCH_WINDOW" envDefault:"720h"`
	StoreIP            string        `env:"NAZR_STORE_IP" envDefault:"raw"`
	IPHashSalt         string        `env:"NAZR_IP_HASH_SALT" secret:"true"`
	StoreComponents    bool          `env:"NAZR_STORE_COMPONENTS" envDefault:"false"`
	EventRetention     time.Duration `env:"NAZR_EVENT_RETENTION" envDefault:"2160h"`
	LogRetention       time.Duration `env:"NAZR_LOG_RETENTION"`

	// Widget challenge and tokens.
	PowBits             int           `env:"NAZR_POW_BITS" envDefault:"18"` // leading zero bits; 0 disables proof-of-work
	WidgetTokenTTL      time.Duration `env:"NAZR_WIDGET_TOKEN_TTL" envDefault:"5m"`
	WidgetIssuer        string        `env:"NAZR_WIDGET_ISSUER"`
	WidgetPassMaxDanger int           `env:"NAZR_WIDGET_PASS_MAX_DANGER" envDefault:"2"`
}

// AddrOff is the NAZR_HTTP_ADDR / NAZR_METRICS_ADDR value (case-insensitive)
// that disables that listener. Load turns it into an empty address. An empty
// value cannot: the env library treats it as unset and applies the default.
const AddrOff = "off"

// Load reads configuration through lookup, which receives full variable names
// such as "NAZR_TLS_MODE". The process environment is never consulted.
func Load(lookup func(string) (string, bool)) (Config, error) {
	environ := map[string]string{}
	t := reflect.TypeFor[Config]()
	for i := range t.NumField() {
		key := t.Field(i).Tag.Get("env")
		if v, ok := lookup(key); ok {
			environ[key] = v
		}
	}
	var c Config
	if err := env.ParseWithOptions(&c, env.Options{Environment: environ}); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	v := reflect.ValueOf(&c).Elem()
	for i := range v.NumField() {
		if f := v.Field(i); f.Type() == reflect.TypeFor[[]string]() {
			f.Set(reflect.ValueOf(cleanList(f.Interface().([]string))))
		}
	}
	// An empty value counts as unset (and so as the default); "off" disables
	// the HTTP and metrics listeners.
	for _, a := range []*string{&c.HTTPAddr, &c.MetricsAddr} {
		if strings.EqualFold(strings.TrimSpace(*a), AddrOff) {
			*a = ""
		}
	}
	if c.ACMEDir == "" && len(c.ACMEDomains) > 0 {
		c.ACMEDir = filepath.Join(c.DataDir, "acme")
	}
	return c, nil
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Validate checks cross-field and enumerated constraints.
func (c Config) Validate() error {
	var errs []error
	switch c.TLSMode {
	case "terminate", "proxied", "plain":
	default:
		errs = append(errs, fmt.Errorf("NAZR_TLS_MODE: %q is not one of terminate|proxied|plain", c.TLSMode))
	}
	if len(c.ACMEDomains) > 0 && (c.TLSCertPEM != "" || c.TLSKeyPEM != "") {
		errs = append(errs, errors.New("NAZR_ACME_DOMAINS cannot be combined with NAZR_TLS_CERT_PEM/NAZR_TLS_KEY_PEM"))
	}
	if (c.TLSCertPEM == "") != (c.TLSKeyPEM == "") {
		errs = append(errs, errors.New("NAZR_TLS_CERT_PEM and NAZR_TLS_KEY_PEM: set both or neither"))
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("NAZR_TLS_CERT_FILE and NAZR_TLS_KEY_FILE: set both or neither"))
	}
	switch c.StoreIP {
	case "raw", "hash":
	default:
		errs = append(errs, fmt.Errorf("NAZR_STORE_IP: %q is not one of raw|hash", c.StoreIP))
	}
	if c.CollectSampleRate < 0 || c.CollectSampleRate > 1 {
		errs = append(errs, fmt.Errorf("NAZR_COLLECT_SAMPLE_RATE: %v is outside [0,1]", c.CollectSampleRate))
	}
	if c.BodyLimit <= 0 {
		errs = append(errs, fmt.Errorf("NAZR_BODY_LIMIT: %d must be greater than 0", c.BodyLimit))
	}
	if c.PowBits < 0 || c.PowBits > 32 {
		errs = append(errs, fmt.Errorf("NAZR_POW_BITS: %d is outside [0,32]", c.PowBits))
	}
	if c.WidgetTokenTTL <= 0 {
		errs = append(errs, fmt.Errorf("NAZR_WIDGET_TOKEN_TTL: %v must be greater than 0", c.WidgetTokenTTL))
	}
	if c.WidgetPassMaxDanger < 0 || c.WidgetPassMaxDanger > 5 {
		errs = append(errs, fmt.Errorf("NAZR_WIDGET_PASS_MAX_DANGER: %d is outside [0,5]", c.WidgetPassMaxDanger))
	}
	return errors.Join(errs...)
}

// Redacted returns every setting keyed by its NAZR_* name as a string, with
// set secrets replaced by "<redacted>". Unset secrets stay empty.
func (c Config) Redacted() map[string]string {
	out := map[string]string{}
	v := reflect.ValueOf(c)
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		s := format(v.Field(i))
		if sf.Tag.Get("secret") == "true" && s != "" {
			s = redacted
		}
		out[sf.Tag.Get("env")] = s
	}
	return out
}

func format(f reflect.Value) string {
	switch x := f.Interface().(type) {
	case []string:
		return strings.Join(x, ",")
	case time.Duration:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}
