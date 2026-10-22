package ipintel

import (
	"net/netip"
	"os"
	"reflect"
	"testing"
)

func TestParseAppleCSV(t *testing.T) {
	f, err := os.Open(td("apple.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pt, err := parseAppleCSV(f)
	if err != nil {
		t.Fatal(err)
	}
	if pt.Rows() != 10 {
		t.Errorf("rows = %d, want 10", pt.Rows())
	}
	r, ok := pt.Lookup(netip.MustParseAddr("172.224.226.5"))
	if !ok || r != (relayEntry{"GB", "GB-EN", "London"}) {
		t.Errorf("v4 hit = %+v %v", r, ok)
	}
	if r, ok := pt.Lookup(netip.MustParseAddr("2a09:bac1:1500::1")); !ok || r.City != "Amsterdam" {
		t.Errorf("v6 hit = %+v %v", r, ok)
	}
	if _, ok := pt.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("8.8.8.8 should miss")
	}
}

func TestParseTorList(t *testing.T) {
	pt, err := loadCIDRFile(td("tor.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Rows() != 5 {
		t.Errorf("rows = %d, want 5", pt.Rows())
	}
	if _, ok := pt.Lookup(netip.MustParseAddr("185.220.101.1")); !ok {
		t.Error("exit should hit")
	}
	if _, ok := pt.Lookup(netip.MustParseAddr("2a0b:f4c2::1")); !ok {
		t.Error("v6 exit should hit")
	}
	if _, ok := pt.Lookup(netip.MustParseAddr("185.220.101.3")); ok {
		t.Error("neighbour should miss")
	}
}

func TestParseCIDRListSkipsCommentsAndGarbage(t *testing.T) {
	pt, err := loadCIDRFile(td("dc-v4.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Rows() != 3 {
		t.Errorf("dc rows = %d, want 3", pt.Rows())
	}
	for _, ip := range []string{"203.0.113.5", "198.51.100.200", "192.0.2.100"} {
		if _, ok := pt.Lookup(netip.MustParseAddr(ip)); !ok {
			t.Errorf("%s should hit", ip)
		}
	}
	if _, ok := pt.Lookup(netip.MustParseAddr("192.0.2.200")); ok {
		t.Error("192.0.2.200 is in the vpn list, not datacenter")
	}
	vpn, err := loadCIDRFile(td("vpn-v4.txt"))
	if err != nil || vpn.Rows() != 3 {
		t.Fatalf("vpn rows = %v, err %v", vpn, err)
	}
	if _, ok := vpn.Lookup(netip.MustParseAddr("192.0.2.200")); !ok {
		t.Error("vpn should hit 192.0.2.200")
	}
}

func TestParseCIDRListRejectsGarbage(t *testing.T) {
	if _, err := parseCIDRList(stringsReader("<html>nope</html>\n")); err == nil {
		t.Error("html body should be rejected")
	}
}

func TestParseJA4DB(t *testing.T) {
	tb, err := loadJA4DBFile(td("ja4db.json"))
	if err != nil {
		t.Fatal(err)
	}
	if tb.Rows() != 2 {
		t.Errorf("rows = %d, want 2 (records without application or ja4 skipped)", tb.Rows())
	}
	got := tb.Families("t13d1516h2_8daaf6152771_02713d6af862")
	if want := []string{"chrome", "chromium"}; !reflect.DeepEqual(got, want) {
		t.Errorf("families = %v, want %v", got, want)
	}
	if got := tb.Families("t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"); !reflect.DeepEqual(got, []string{"curl"}) {
		t.Errorf("curl families = %v", got)
	}
	if got := tb.Families("unknown"); got == nil || len(got) != 0 {
		t.Errorf("unknown = %#v, want empty non-nil", got)
	}
}

func TestMaxMindTablesLoad(t *testing.T) {
	city, err := openMMDB(td("GeoLite2-City-Test.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := city.Lookup(netip.MustParseAddr(testCityIP))
	if !ok || rec.Country.ISOCode != "GB" || rec.City.Names["en"] != "Boxford" {
		t.Errorf("city = %+v %v", rec, ok)
	}
	if _, ok := city.Lookup(netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("10.0.0.1 should miss")
	}
	asn, err := openMMDB(td("GeoLite2-ASN-Test.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	rec, ok = asn.Lookup(netip.MustParseAddr(testASNIP))
	if !ok || rec.ASN == 0 || rec.ASOrg == "" {
		t.Errorf("asn = %+v %v", rec, ok)
	}
}
