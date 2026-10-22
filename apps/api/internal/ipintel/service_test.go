package ipintel

import (
	"net/netip"
	"testing"
)

func TestLookupBeforeLoadIsZero(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), HTTPClient: noNetClient()})
	if err != nil {
		t.Fatal(err)
	}
	if l := s.Lookup(netip.MustParseAddr("203.0.113.5")); l != (Lookup{}) {
		t.Errorf("lookup = %+v, want zero", l)
	}
	if l := s.Lookup(netip.Addr{}); l != (Lookup{}) {
		t.Errorf("invalid addr lookup = %+v", l)
	}
	if got := s.JA4Families("x"); got == nil || len(got) != 0 {
		t.Errorf("JA4Families = %#v", got)
	}
}

func TestLookupCombinesSources(t *testing.T) {
	s := seededService(t)
	l := s.Lookup(netip.MustParseAddr(testASNIP))
	if l.ASN == 0 || l.ASOrg == "" {
		t.Errorf("asn missing: %+v", l)
	}
	l = s.Lookup(netip.MustParseAddr("185.220.101.1"))
	if !l.Tor || l.VPN || l.Datacenter {
		t.Errorf("tor flags = %+v", l)
	}
	l = s.Lookup(netip.MustParseAddr("192.0.2.200"))
	if !l.VPN || l.Datacenter {
		t.Errorf("vpn flags = %+v", l)
	}
	l = s.Lookup(netip.MustParseAddr("203.0.113.5"))
	if !l.Datacenter || l.GeoSource != "" {
		t.Errorf("dc flags = %+v", l)
	}
	if got := s.JA4Families("t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"); len(got) != 1 || got[0] != "curl" {
		t.Errorf("families = %v", got)
	}
}

func TestLookupMapsIPv4MappedIPv6(t *testing.T) {
	s := seededService(t)
	for _, ip := range []string{"203.0.113.5", testCityIP, "185.220.101.1"} {
		plain := s.Lookup(netip.MustParseAddr(ip))
		mapped := s.Lookup(netip.AddrFrom16(netip.MustParseAddr(ip).As16()))
		if plain != mapped {
			t.Errorf("%s: plain %+v != mapped %+v", ip, plain, mapped)
		}
	}
	if !s.Lookup(netip.MustParseAddr("::ffff:203.0.113.5")).Datacenter {
		t.Error("::ffff:203.0.113.5 should be datacenter")
	}
}

func TestMaxMindGeoWithoutApple(t *testing.T) {
	s := seededService(t)
	// Drop Apple so the address only has MaxMind data.
	s.entries["apple"].tbl.Store(nil)
	l := s.Lookup(netip.MustParseAddr(testCityIP))
	if l.GeoSource != "maxmind" || l.Country != "GB" || l.City != "Boxford" || l.ContinentCode != "EU" ||
		l.CountryName != "United Kingdom" || l.ContinentName != "Europe" || l.PrivateRelay {
		t.Errorf("lookup = %+v", l)
	}
	if l.Region != "GB-ENG" {
		t.Errorf("region = %q", l.Region)
	}
}

func TestAppleOverridesGeo(t *testing.T) {
	s := seededService(t)
	l := s.Lookup(netip.MustParseAddr(testCityIP))
	if !l.PrivateRelay || l.GeoSource != "apple" || l.City != "London" || l.Region != "GB-EN" || l.Country != "GB" {
		t.Errorf("lookup = %+v", l)
	}
}

func TestComponentAndIdentifier(t *testing.T) {
	s := seededService(t)
	a := netip.MustParseAddr("::ffff:185.220.101.1")
	c := Component(a, s.Lookup(a))
	if c["address"] != "185.220.101.1" || c["version"] != "v4" || c["tor"] != true || c["asn"] != uint32(0) ||
		c["vpn"] != false || c["private_relay"] != false || c["country"] != "" {
		t.Errorf("component = %#v", c)
	}
	if len(c) != 11 {
		t.Errorf("component has %d keys", len(c))
	}
	if Component(netip.MustParseAddr("2001:db8::1"), Lookup{})["version"] != "v6" {
		t.Error("v6 version")
	}
	id := Identifier(netip.MustParseAddr("203.0.113.5"), "salt")
	if len(id) != 16 || id != Identifier(netip.MustParseAddr("203.0.113.5"), "salt") || id == Identifier(netip.MustParseAddr("203.0.113.5"), "other") {
		t.Errorf("id = %q", id)
	}
	if want := sum([]byte("salt203.0.113.5"))[:16]; id != want {
		t.Errorf("id = %q, want %q", id, want)
	}
}
