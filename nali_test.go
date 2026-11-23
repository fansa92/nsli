package main

import "testing"

func TestGeoInfoString(t *testing.T) {
	cases := []struct {
		name string
		in   GeoInfo
		want string
	}{
		{
			name: "全部字段",
			in:   GeoInfo{Country: "中国", Region: "广东省", City: "深圳市", ISP: "Chinanet"},
			want: "  [中国 广东省 深圳市 Chinanet]",
		},
		{
			name: "重复字段去重",
			in:   GeoInfo{Country: "中国", Region: "中国", City: "北京", ISP: ""},
			want: "  [中国 北京]",
		},
		{
			name: "空字段跳过",
			in:   GeoInfo{Country: "美国", ISP: "Google LLC"},
			want: "  [美国 Google LLC]",
		},
		{
			name: "全空返回空串",
			in:   GeoInfo{},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.String(); got != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestProviderParse(t *testing.T) {
	ps := providers()
	if len(ps) < 3 {
		t.Fatalf("expected at least 3 providers, got %d", len(ps))
	}

	t.Run("ip-api", func(t *testing.T) {
		body := []byte(`{"status":"success","country":"中国","regionName":"山东","city":"济南市","isp":"China Unicom Shandong Province network","org":""}`)
		info := ps[0].parse(body)
		if info == nil {
			t.Fatal("parse returned nil")
		}
		if info.Country != "中国" || info.Region != "山东" || info.City != "济南市" {
			t.Errorf("unexpected geo: %+v", info)
		}
		if want := "  [中国 山东 济南市 China Unicom Shandong]"; info.String() != want {
			t.Errorf("String() = %q, want %q", info.String(), want)
		}
	})

	t.Run("ip-api fail status", func(t *testing.T) {
		body := []byte(`{"status":"fail"}`)
		if info := ps[0].parse(body); info != nil {
			t.Errorf("expected nil for fail status, got %+v", info)
		}
	})

	t.Run("ip.sb", func(t *testing.T) {
		body := []byte(`{"country":"United States","region":"California","city":"Mountain View","isp":"Google","organization":"Google LLC"}`)
		info := ps[1].parse(body)
		if info == nil {
			t.Fatal("parse returned nil")
		}
		if info.Country != "United States" {
			t.Errorf("unexpected country: %q", info.Country)
		}
	})

	t.Run("ipwho.is", func(t *testing.T) {
		body := []byte(`{"success":true,"country":"Singapore","region":"North West","city":"Singapore","connection":{"isp":"","org":"Aceville Pte.ltd"}}`)
		info := ps[2].parse(body)
		if info == nil {
			t.Fatal("parse returned nil")
		}
		if info.ISP != "Aceville Pte.ltd" {
			t.Errorf("expected fallback org as ISP, got %q", info.ISP)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		for i, p := range ps {
			if info := p.parse([]byte(`<html>rate limited</html>`)); info != nil {
				t.Errorf("provider %d: expected nil on bad json", i)
			}
		}
	})
}

func TestPickISP(t *testing.T) {
	if got := pickISP("Google LLC", "SomeNet"); got != "SomeNet" {
		t.Errorf("expected cloud vendor to be skipped, got %q", got)
	}
	if got := pickISP("Google LLC"); got != "Google LLC" {
		t.Errorf("expected fallback when only vendor present, got %q", got)
	}
	if got := pickISP("", ""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestShorten(t *testing.T) {
	cases := map[string]string{
		"Chinanet":                                  "Chinanet",
		"China Unicom Shandong Province network":    "China Unicom Shandong",
		"Shenzhen Tencent Computer Systems Company": "Shenzhen Tencent Compute…",
	}
	for in, want := range cases {
		if got := shorten(in); got != want {
			t.Errorf("shorten(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameHelpers(t *testing.T) {
	if trimDot("example.com.") != "example.com" {
		t.Error("trimDot failed")
	}
	if !sameName("A.Example.COM.", "a.example.com") {
		t.Error("sameName should be case-insensitive and dot-insensitive")
	}
}

func TestIsSupportedType(t *testing.T) {
	for _, ok := range []string{
		"A", "AAAA", "A+AAAA", "ANY", "CNAME", "MX", "TXT", "NS", "SRV",
		"PTR", "SOA", "CAA", "DNSKEY", "DS", "TLSA", "NAPTR", "HINFO", "SPF",
	} {
		if !isSupportedType(ok) {
			t.Errorf("%s should be supported", ok)
		}
	}
	for _, bad := range []string{"", "a", "PTR2", "BOGUS"} {
		if isSupportedType(bad) {
			t.Errorf("%q should not be supported", bad)
		}
	}
}

func TestSplitIPs(t *testing.T) {
	list := []hostIP{
		{addr: "8.8.8.8", public: true},
		{addr: "192.168.1.1", public: false},
		{addr: "2001:4860::8888", public: true},
	}
	addrs, ips := splitIPs(list)
	if len(addrs) != 3 {
		t.Errorf("addrs = %v, want 3 entries", addrs)
	}
	if len(ips) != 2 || ips[0] != "8.8.8.8" || ips[1] != "2001:4860::8888" {
		t.Errorf("ips = %v, want [8.8.8.8 2001:4860::8888]", ips)
	}
}
