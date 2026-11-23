package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestNameCodec(t *testing.T) {
	enc, err := encodeName("www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Equal(enc, want) {
		t.Fatalf("encodeName = %v, want %v", enc, want)
	}
	msg := append(append([]byte{}, enc...), 0xc0, 0x00)
	got, end, err := decodeName(msg, len(enc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "www.example.com" || end != len(enc)+2 {
		t.Fatalf("decodeName = %q, end=%d", got, end)
	}
}

func TestParseDNSMessage(t *testing.T) {
	name, _ := encodeName("example.com")
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf, 0x1234)
	binary.BigEndian.PutUint16(buf[2:], 0x8180) // QR + RD + RA
	binary.BigEndian.PutUint16(buf[4:], 1)
	binary.BigEndian.PutUint16(buf[6:], 1)
	buf = append(buf, name...)
	buf = append(buf, 0, 1, 0, 1) // A / IN
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4}
	buf = append(buf, rr...)
	m, err := parseDNSMessage(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !m.QR || !m.RD || m.Rcode != 0 {
		t.Fatalf("bad header: %+v", m)
	}
	if len(m.Answers) != 1 || m.Answers[0].Data != "1.2.3.4" || m.Answers[0].TTL != 30 {
		t.Fatalf("bad answers: %+v", m.Answers)
	}
	var b bytes.Buffer
	m.DebugDump(2, &b)
	if !strings.Contains(b.String(), "ttl=30") {
		t.Fatalf("debug dump missing TTL: %s", b.String())
	}
}

func TestParseRRTypes(t *testing.T) {
	cases := []struct {
		typ  uint16
		data []byte
		want string
	}{
		{typeMX, []byte{0, 10, 3, 'm', 'x', '1', 0}, "10 mx1"},
		{typeTXT, []byte{5, 'h', 'e', 'l', 'l', 'o'}, "hello"},
		{typeCAA, []byte{0, 5, 'i', 's', 's', 'u', 'e', 'x', 'y', 'z'}, "0 issue \"xyz\""},
		{typeCNAME, []byte{3, 'a', 'b', 'c', 0}, "abc"},
	}
	for _, c := range cases {
		got, err := rdataText(c.typ, c.data)
		if err != nil {
			t.Errorf("type %d: %v", c.typ, err)
			continue
		}
		if got != c.want {
			t.Errorf("type %d: got %q, want %q", c.typ, got, c.want)
		}
	}
}

func TestReversePTR(t *testing.T) {
	got, err := reversePTR("1.1.1.1")
	if err != nil || got != "1.1.1.1.in-addr.arpa" {
		t.Fatalf("reversePTR v4 = %q, %v", got, err)
	}
	got, err = reversePTR("2001:4860:4860::8888")
	if err != nil || !strings.HasSuffix(got, ".ip6.arpa") {
		t.Fatalf("reversePTR v6 = %q, %v", got, err)
	}
}

func TestCDNVendor(t *testing.T) {
	if got := cdnVendor("www.gov.cn.bsgslb.cn"); got != "白山云 CDN" {
		t.Fatalf("cdnVendor = %q", got)
	}
	if got := cdnVendor("d1234.akamaiedge.net"); got != "Akamai CDN" {
		t.Fatalf("cdnVendor = %q", got)
	}
	if got := cdnVendor("www.example.com"); got != "" {
		t.Fatalf("cdnVendor should be empty, got %q", got)
	}
}

func TestAnnotateLine(t *testing.T) {
	line := "ip 8.8.8.8 and 192.168.1.1"
	got := annotateLine(line, textOptions{
		geo: NewGeoLookup(time.Second, true), color: "never", markPrivate: true, lang: "zh",
	})
	if !strings.Contains(got, "192.168.1.1  [局域网 IP]") {
		t.Fatalf("private IP not marked: %s", got)
	}
	if strings.Contains(got, "8.8.8.8  [局域网") {
		t.Fatalf("public IP wrongly marked as private: %s", got)
	}
}
