package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// qqwryDB 读取纯真 IPv4 离线数据库（qqwry.dat）。
type qqwryDB struct {
	data       []byte
	first, last uint32
	path       string
}

func naliHome() string {
	if v := strings.TrimSpace(os.Getenv("NALI_HOME")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("NALI_DB_HOME")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "nali")
		}
	}
	return filepath.Join(os.Getenv("HOME"), ".local", "share", "nali")
}

func qqwryPath() string {
	if v := strings.TrimSpace(os.Getenv("NALI_DB_FILE")); v != "" {
		return v
	}
	return filepath.Join(naliHome(), "qqwry.dat")
}

func openQQWry(path string) (*qqwryDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, errors.New("纯真数据库文件过短")
	}
	q := &qqwryDB{
		data:  b,
		first: binary.LittleEndian.Uint32(b[0:4]),
		last:  binary.LittleEndian.Uint32(b[4:8]),
		path:  path,
	}
	if q.first > q.last || uint64(q.last)+7 > uint64(len(b)) {
		return nil, errors.New("纯真数据库索引范围无效")
	}
	return q, nil
}

func u24(b []byte) int {
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16
}

// readString 读取以 0 结尾的字符串，必要时跟随重定向指针。
func (q *qqwryDB) readString(off int, depth int) (string, int) {
	if off < 0 || off >= len(q.data) || depth > 4 {
		return "", off + 1
	}
	flag := q.data[off]
	if flag == 0x01 || flag == 0x02 {
		if off+4 > len(q.data) {
			return "", off + 1
		}
		redirect := u24(q.data[off+1 : off+4])
		s, _ := q.readString(redirect, depth+1)
		if flag == 0x01 {
			area, next := q.readString(off+4, depth+1)
			if area != "" {
				return s + " " + area, next
			}
		}
		return s, off + 4
	}
	end := bytes.IndexByte(q.data[off:], 0)
	if end < 0 {
		end = len(q.data) - off
	}
	return decodeGBK(q.data[off : off+end]), off + end + 1
}

func cleanQQWry(s string) string {
	s = strings.TrimSpace(s)
	for _, junk := range []string{" CZ88.NET", " CZ88.NET.", " LAN", " xxx" , " 纯真网络"} {
		s = strings.ReplaceAll(s, junk, "")
	}
	return strings.TrimSpace(s)
}

// Lookup 按 IP 查询纯真库，返回国家与地区。
func (q *qqwryDB) Lookup(ipStr string) (string, string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return "", "", errors.New("纯真库只支持 IPv4")
	}
	target := binary.BigEndian.Uint32(ip.To4())
	lo, hi := int(q.first), int(q.last)
	for lo <= hi {
		mid := lo + ((hi-lo)/7)*7
		if mid < int(q.first) || mid+7 > len(q.data) {
			break
		}
		// 纯真库索引的 IP 以小端数值存储，查询 IP 为大端数值（与 nali 一致）。
		start := binary.LittleEndian.Uint32(q.data[mid : mid+4])
		if target < start {
			hi = mid - 7
			continue
		}
		hit := mid == int(q.last)
		if !hit && mid+11 <= len(q.data) {
			hit = target < binary.LittleEndian.Uint32(q.data[mid+7:mid+11])
		}
		if hit {
			// 纯真库的 3 字节记录偏移需要 +4 才是文件绝对偏移。
			return q.readRecord(u24(q.data[mid+4:mid+7]) + 4)
		}
		lo = mid + 7
	}
	return "", "", nil
}

func (q *qqwryDB) readRecord(offset int) (string, string, error) {
	if offset < 0 || offset >= len(q.data) {
		return "", "", errors.New("记录偏移越界")
	}
	var country, area string
	switch q.data[offset] {
	case 0x01:
		if offset+4 > len(q.data) {
			return "", "", errors.New("重定向记录截断")
		}
		country, _ = q.readString(u24(q.data[offset+1:offset+4]), 1)
		area, _ = q.readString(offset+4, 1)
	case 0x02:
		if offset+7 > len(q.data) {
			return "", "", errors.New("双重重定向记录截断")
		}
		country, _ = q.readString(u24(q.data[offset+1:offset+4]), 1)
		area, _ = q.readString(u24(q.data[offset+4:offset+7]), 1)
	default:
		var next int
		country, next = q.readString(offset, 1)
		area, _ = q.readString(next, 1)
	}
	return cleanQQWry(country), cleanQQWry(area), nil
}

// Geo 把纯真库结果映射成统一归属地结构。
func (q *qqwryDB) Geo(ip string) *GeoInfo {
	country, area, err := q.Lookup(ip)
	if err != nil || (country == "" && area == "") {
		return nil
	}
	region, city := area, ""
	if i := strings.IndexAny(area, "  "); i > 0 {
		region, city = area[:i], strings.TrimSpace(area[i:])
	}
	return &GeoInfo{IP: ip, Country: country, Region: region, City: city, Source: "qqwry"}
}
