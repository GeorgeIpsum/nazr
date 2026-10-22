package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ListenAddr": ":443", "HTTPAddr": ":80", "MetricsAddr": "127.0.0.1:9090",
		"TLSMode": "terminate", "JA4Header": "x-ja4", "ClientIPHeader": "x-forwarded-for",
		"DefaultRateLimit": 600, "BodyLimit": 262144, "DataDir": "/data",
		"AutoMigrate": true, "LogLevel": "info", "LogFormat": "json",
		"MaxMindEditions":    []string{"GeoLite2-City", "GeoLite2-ASN"},
		"VisitorMatchWindow": 720 * time.Hour, "StoreIP": "raw", "StoreComponents": false,
		"EventRetention": 2160 * time.Hour, "UAJA4MinObservations": 20,
		"CollectSampleRate": 0.01, "CORSOrigins": []string{"*"},
	}
	v := reflect.ValueOf(c)
	for f, w := range want {
		if got := v.FieldByName(f).Interface(); !reflect.DeepEqual(got, w) {
			t.Errorf("%s = %#v, want %#v", f, got, w)
		}
	}
	if err := c.Validate(); err != nil {
		t.Errorf("defaults should validate: %v", err)
	}
}

func TestLoadParsesDurationsAndLists(t *testing.T) {
	c, err := Load(lookupFrom(map[string]string{
		"NAZR_EVENT_RETENTION":         "24h",
		"NAZR_MAXMIND_EDITIONS":        "GeoLite2-ASN",
		"NAZR_TRUSTED_PROXIES":         "10.0.0.0/8, 192.168.0.0/16",
		"NAZR_UA_JA4_MIN_OBSERVATIONS": "5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.EventRetention != 24*time.Hour {
		t.Errorf("EventRetention = %v", c.EventRetention)
	}
	if !reflect.DeepEqual(c.MaxMindEditions, []string{"GeoLite2-ASN"}) {
		t.Errorf("MaxMindEditions = %#v", c.MaxMindEditions)
	}
	if !reflect.DeepEqual(c.TrustedProxies, []string{"10.0.0.0/8", "192.168.0.0/16"}) {
		t.Errorf("TrustedProxies = %#v", c.TrustedProxies)
	}
	if c.UAJA4MinObservations != 5 {
		t.Errorf("UAJA4MinObservations = %d", c.UAJA4MinObservations)
	}
}

func TestLoadIgnoresProcessEnv(t *testing.T) {
	t.Setenv("NAZR_LOG_LEVEL", "debug")
	c, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel != "info" {
		t.Errorf("process env leaked: %q", c.LogLevel)
	}
}

func TestValidateRejectsACMEWithInlinePEM(t *testing.T) {
	c, err := Load(lookupFrom(map[string]string{
		"NAZR_ACME_DOMAINS": "a.example.com",
		"NAZR_TLS_CERT_PEM": "cert",
		"NAZR_TLS_KEY_PEM":  "key",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "NAZR_ACME_DOMAINS") {
		t.Fatalf("want ACME error naming variable, got %v", err)
	}
}

func TestValidateRejectsUnknownTLSMode(t *testing.T) {
	c, err := Load(lookupFrom(map[string]string{"NAZR_TLS_MODE": "bogus"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "NAZR_TLS_MODE") {
		t.Fatalf("want TLS mode error naming variable, got %v", err)
	}
}

func TestValidateOtherRules(t *testing.T) {
	for k, v := range map[string]string{
		"NAZR_STORE_IP":            "plain",
		"NAZR_COLLECT_SAMPLE_RATE": "1.5",
		"NAZR_BODY_LIMIT":          "0",
	} {
		c, err := Load(lookupFrom(map[string]string{k: v}))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%s: want error naming variable, got %v", k, v, err)
		}
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	secrets := map[string]string{
		"NAZR_DATABASE_URL": "postgres://u:p@h/db", "NAZR_REDIS_URL": "redis://:p@h",
		"NAZR_TLS_KEY_PEM": "KEY", "NAZR_MAXMIND_LICENSE_KEY": "lic",
		"NAZR_ADMIN_TOKEN": "tok", "NAZR_IP_HASH_SALT": "salt", "NAZR_JA4DB_TOKEN": "ja4tok",
	}
	in := map[string]string{"NAZR_LOG_LEVEL": "debug"}
	for k, v := range secrets {
		in[k] = v
	}
	c, err := Load(lookupFrom(in))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Redacted()
	for k := range secrets {
		if r[k] != "<redacted>" {
			t.Errorf("%s = %q, want redacted", k, r[k])
		}
	}
	if r["NAZR_LOG_LEVEL"] != "debug" {
		t.Errorf("LOG_LEVEL = %q", r["NAZR_LOG_LEVEL"])
	}
	// Unset secrets stay empty rather than claiming to be redacted.
	c2, _ := Load(lookupFrom(nil))
	if got := c2.Redacted()["NAZR_ADMIN_TOKEN"]; got != "" {
		t.Errorf("unset secret = %q, want empty", got)
	}
}
