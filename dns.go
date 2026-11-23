package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSResult 是单个目标的查询结果(同时用于 JSON 输出)。
type DNSResult struct {
	Query     string    `json:"query"`
	Type      string    `json:"type"`
	CNAMEs    []string  `json:"cnames,omitempty"`
	Addresses []string  `json:"addresses,omitempty"`
	IPs       []string  `json:"-"`
	MXs       []string  `json:"mx,omitempty"`
	TXTs      []string  `json:"txt,omitempty"`
	NSs       []string  `json:"ns,omitempty"`
	SRVs      []string  `json:"srv,omitempty"`
	Geo       []GeoInfo `json:"geo,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// newResolver 构造解析器。server 为空时使用系统 DNS, 否则使用指定服务器(裸 UDP)。
func newResolver(server string, timeout time.Duration) *net.Resolver {
	if server == "" {
		return &net.Resolver{PreferGo: false}
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	d := net.Dialer{Timeout: timeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, server)
		},
	}
}

// hostIP 是一个解析出的地址: 显示文本 + 是否为可查归属地的公网 IP。
type hostIP struct {
	addr   string
	public bool
}

// lookupIPs 查询 A/AAAA 记录。
// qtype 为 A/AAAA 时只保留对应族的地址, ANY 时两族都要。
func lookupIPs(ctx context.Context, r *net.Resolver, name, qtype string) (out []hostIP, err error) {
	addrsAll, err := r.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, a := range addrsAll {
		switch qtype {
		case "A":
			if a.IP.To4() == nil {
				continue
			}
		case "AAAA":
			if a.IP.To4() != nil {
				continue
			}
		}
		s := a.String()
		if i := strings.IndexByte(s, '%'); i >= 0 { // 去掉 zone id
			s = s[:i]
		}
		ip := a.IP
		public := ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
		out = append(out, hostIP{addr: s, public: public})
	}
	return out, nil
}

// splitIPs 把 hostIP 列表拆成显示地址与公网 IP 两列。
func splitIPs(list []hostIP) (addrs, ips []string) {
	for _, h := range list {
		addrs = append(addrs, h.addr)
		if h.public {
			ips = append(ips, h.addr)
		}
	}
	return addrs, ips
}

// reverseName 反向解析服务器名称, 失败返回空串。
func reverseName(ctx context.Context, r *net.Resolver, server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return trimDot(names[0])
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func sameName(a, b string) bool { return strings.EqualFold(trimDot(a), trimDot(b)) }

// cleanDNSError 把 Go 解析错误转换成 nslookup 风格的简短消息。
func cleanDNSError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "no records found (Non-existent domain)"
		case dnsErr.IsTemporary:
			return fmt.Sprintf("temporary DNS failure: %s", dnsErr.Err)
		case dnsErr.IsTimeout:
			return "DNS query timed out"
		}
		return dnsErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Sprintf("连接 DNS 服务器失败: %s", opErr)
	}
	return err.Error()
}
