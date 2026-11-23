package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// zxIPv6DB 读取 ZX IPv6 离线库（IPDB / ipv6wry.db，nali 的默认 IPv6 库）。
//
// 文件格式（24 字节头 + 11 字节/条索引 + 记录区）：
//
//	[0:4]   "IPDB"
//	[6]     offLen（偏移字节数，通常为 3）
//	[7]     ipLen（IP 字节数，通常为 8）
//	[8:16]  counts（uint64 LE，索引条数）
//	[16:24] start（uint64 LE，索引起始偏移）
type zxIPv6DB struct {
	data          []byte
	offLen, ipLen int
	count         uint64
	start         uint64
	path          string
}

func zxIPv6Path() string {
	if v := strings.TrimSpace(os.Getenv("NALI_IP6_FILE")); v != "" {
		return v
	}
	return filepath.Join(naliHome(), "ipv6wry.db")
}

func bytes3ToUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func parseZXIPv6(data []byte) (*zxIPv6DB, error) {
	if len(data) < 24 || string(data[:4]) != "IPDB" {
		return nil, errors.New("不是有效的 IPDB 文件")
	}
	offLen, ipLen := int(data[6]), int(data[7])
	if offLen != 3 || ipLen != 8 {
		return nil, fmt.Errorf("不支持的 IPDB 格式 (offLen=%d ipLen=%d)", offLen, ipLen)
	}
	count := binary.LittleEndian.Uint64(data[8:16])
	start := binary.LittleEndian.Uint64(data[16:24])
	entryLen := uint64(offLen + ipLen)
	end := start + count*entryLen
	if count == 0 || start >= end || end > uint64(len(data)) {
		return nil, errors.New("IPDB 索引范围无效")
	}
	return &zxIPv6DB{data: data, offLen: offLen, ipLen: ipLen, count: count, start: start}, nil
}

func openZXIPv6(path string) (*zxIPv6DB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	db, err := parseZXIPv6(b)
	if err == nil {
		db.path = path
	}
	return db, err
}

// Lookup 查询 IPv6 地址对应的国家与地区。
func (z *zxIPv6DB) Lookup(ipStr string) (string, string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() != nil {
		return "", "", errors.New("ZX IPv6 库只支持 IPv6 地址")
	}
	target := binary.BigEndian.Uint64(ip.To16()[:8])
	entryLen := uint64(z.offLen + z.ipLen)
	lo, hi := z.start, z.start+(z.count-1)*entryLen
	var found uint32
	for lo <= hi {
		mid := lo + (hi-lo)/2/entryLen*entryLen
		if mid+entryLen > uint64(len(z.data)) {
			break
		}
		entry := z.data[mid : mid+entryLen]
		indexIP := binary.LittleEndian.Uint64(entry[:8])
		if target < indexIP {
			if mid == lo {
				break
			}
			hi = mid - entryLen
			continue
		}
		found = bytes3ToUint32(entry[8:11])
		if mid == hi {
			break
		}
		lo = mid + entryLen
	}
	if found == 0 {
		return "", "", nil
	}
	country, area := z.parseRecord(int(found), 0)
	return cleanQQWry(country), cleanQQWry(area), nil
}

// parseRecord 复刻 wry.Reader 的重定向语义。
func (z *zxIPv6DB) parseRecord(offset, depth int) (string, string) {
	if depth > 8 || offset < 0 || offset >= len(z.data) {
		return "", ""
	}
	switch z.data[offset] {
	case 0x01:
		if offset+4 > len(z.data) {
			return "", ""
		}
		return z.parseRecord(int(bytes3ToUint32(z.data[offset+1:offset+4])), depth+1)
	case 0x02:
		if offset+4 > len(z.data) {
			return "", ""
		}
		country, _ := z.readString(int(bytes3ToUint32(z.data[offset+1:offset+4])))
		return country, z.readArea(offset + 4)
	default:
		country, next := z.readString(offset)
		return country, z.readArea(next)
	}
}

func (z *zxIPv6DB) readArea(pos int) string {
	if pos < 0 || pos >= len(z.data) {
		return ""
	}
	if z.data[pos] == 0x01 || z.data[pos] == 0x02 {
		if pos+4 > len(z.data) {
			return ""
		}
		ref := int(bytes3ToUint32(z.data[pos+1 : pos+4]))
		if ref == 0 {
			return ""
		}
		s, _ := z.readString(ref)
		return s
	}
	s, _ := z.readString(pos)
	return s
}

func (z *zxIPv6DB) readString(pos int) (string, int) {
	if pos < 0 || pos >= len(z.data) {
		return "", pos + 1
	}
	end := bytes.IndexByte(z.data[pos:], 0)
	if end < 0 {
		end = len(z.data) - pos
	}
	// ZX IPv6 库的文本是 UTF-8（纯真 qqwry 才是 GBK），nali 的 zx 实现也不做 GBK 解码。
	return string(z.data[pos : pos+end]), pos + end + 1
}

// Geo 把 ZX IPv6 库结果映射成统一归属地结构。
func (z *zxIPv6DB) Geo(ip string) *GeoInfo {
	country, area, err := z.Lookup(ip)
	if err != nil || (country == "" && area == "") {
		return nil
	}
	parts := strings.Fields(area)
	region, city := "", ""
	if len(parts) > 0 {
		region = parts[0]
	}
	if len(parts) > 1 {
		city = strings.Join(parts[1:], " ")
	}
	return &GeoInfo{IP: ip, Country: country, Region: region, City: city, Source: "zxipv6wry"}
}
