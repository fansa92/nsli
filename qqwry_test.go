package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 构造一个最小的纯真库：一条索引 1.0.0.0 -> "US"/"California"。
func makeTinyQQWry(t *testing.T) []byte {
	t.Helper()
	rec := append([]byte("United States"), 0)
	rec = append(rec, []byte("California")...)
	rec = append(rec, 0)
	data := make([]byte, 15+len(rec))
	binary.LittleEndian.PutUint32(data[0:4], 8)
	binary.LittleEndian.PutUint32(data[4:8], 8)
	binary.LittleEndian.PutUint32(data[8:12], 0x01000000) // 1.0.0.0 的小端表示
	data[12], data[13], data[14] = 11, 0, 0               // +4 后指向记录区偏移 15
	copy(data[15:], rec)
	return data
}

func TestQQWryLookup(t *testing.T) {
	data := makeTinyQQWry(t)
	q, err := openQQWryBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	country, area, err := q.Lookup("1.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if country != "United States" || area != "California" {
		t.Fatalf("Lookup = %q / %q", country, area)
	}
	if _, _, err := q.Lookup("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	info := q.Geo("1.0.0.1")
	if info == nil || info.Source != "qqwry" || info.Country != "United States" {
		t.Fatalf("Geo = %+v", info)
	}
}

func TestQQWryInvalid(t *testing.T) {
	if _, err := openQQWryBytes(bytes.Repeat([]byte{0}, 4)); err == nil {
		t.Fatal("expected error for short file")
	}
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint32(bad[0:4], 20)
	binary.LittleEndian.PutUint32(bad[4:8], 16)
	if _, err := openQQWryBytes(bad); err == nil {
		t.Fatal("expected error for reversed index range")
	}
}
