package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// 构造最小的 ZX IPv6 库：一条索引 2001:db8::/64 -> "CN"/"Beijing"。
func makeTinyZXDB(t *testing.T) []byte {
	t.Helper()
	rec := append([]byte("CN"), 0)
	rec = append(rec, []byte("Beijing")...)
	rec = append(rec, 0)
	buf := make([]byte, 24+11+len(rec))
	copy(buf[:4], "IPDB")
	buf[6], buf[7] = 3, 8
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	binary.LittleEndian.PutUint64(buf[16:24], 24)
	binary.LittleEndian.PutUint64(buf[24:32], 0x20010db800000000)
	buf[32], buf[33], buf[34] = 35, 0, 0
	copy(buf[35:], rec)
	return buf
}

func TestZXIPv6Lookup(t *testing.T) {
	db, err := parseZXIPv6(makeTinyZXDB(t))
	if err != nil {
		t.Fatal(err)
	}
	country, area, err := db.Lookup("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if country != "CN" || area != "Beijing" {
		t.Fatalf("Lookup = %q / %q", country, area)
	}
	// 同一个 /64 前缀内的地址应命中同一条索引。
	if _, area, err := db.Lookup("2001:db8::abcd"); err != nil || area != "Beijing" {
		t.Fatalf("prefix lookup = %q, %v", area, err)
	}
	if _, _, err := db.Lookup("1.2.3.4"); err == nil {
		t.Fatal("expected error for IPv4 input")
	}
	info := db.Geo("2001:db8::1")
	if info == nil || info.Source != "zxipv6wry" || info.Country != "CN" {
		t.Fatalf("Geo = %+v", info)
	}
}

func TestZXIPv6Invalid(t *testing.T) {
	if _, err := parseZXIPv6([]byte("NOTIPDB")); err == nil {
		t.Fatal("expected error for non-IPDB file")
	}
	b := makeTinyZXDB(t)
	b[7] = 4 // ipLen 必须为 8
	if _, err := parseZXIPv6(b); err == nil {
		t.Fatal("expected error for unsupported ipLen")
	}
}

func TestDualGeoRouting(t *testing.T) {
	off4, err := openQQWryBytes(makeTinyQQWry(t))
	if err != nil {
		t.Fatal(err)
	}
	off6, err := parseZXIPv6(makeTinyZXDB(t))
	if err != nil {
		t.Fatal(err)
	}
	g := NewGeoLookupDual(time.Second, false, off4, off6, false)

	if info := g.Get("1.0.0.1"); info == nil || info.Source != "qqwry" {
		t.Fatalf("IPv4 routing = %+v", info)
	}
	if info := g.Get("2001:db8::1"); info == nil || info.Source != "zxipv6wry" {
		t.Fatalf("IPv6 routing = %+v", info)
	}
	if info := g.Get("0.0.0.1"); info != nil {
		t.Fatalf("unexpected IPv4 result: %+v", info)
	}
	// IP 库的最后一条索引覆盖到地址空间末尾，取更小的前缀才应落空。
	if info := g.Get("2001:db7::1"); info != nil {
		t.Fatalf("unexpected IPv6 result: %+v", info)
	}
}
