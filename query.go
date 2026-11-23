package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// queryEnv 承载一次查询所需的所有配置，交互模式与非交互模式共用。
type queryEnv struct {
	client      *dnsClient
	qtype       uint16
	class       uint16
	rd          bool
	geo         *GeoLookup
	noGeo       bool
	verbose     bool
	color       string
	lang        string
	cdnEnabled  bool
	serverLabel string
	defname     bool
	search      bool
	domain      string
	srchlist    string
	out         *os.File
}

func (e *queryEnv) writer() *os.File {
	if e.out != nil {
		return e.out
	}
	return os.Stdout
}

func (e *queryEnv) serverAddress() string {
	s := e.client.Server
	if host, port, err := net.SplitHostPort(s); err == nil {
		if port == "53" {
			return host + "#53"
		}
		return host + "#" + port
	}
	return s + "#53"
}

// printHeader 打印 nslookup 风格的 Server/Address 两行。
func (e *queryEnv) printHeader() {
	w := e.writer()
	fmt.Fprintf(w, "Server:  %s\n", e.serverLabel)
	addr := e.serverAddress()
	if name := e.reverseServerName(); name != "" {
		fmt.Fprintf(w, "Address:  %s [%s]\n", addr, name)
	} else {
		fmt.Fprintf(w, "Address:  %s\n", addr)
	}
	fmt.Fprintln(w)
}

func (e *queryEnv) reverseServerName() string {
	host, _, err := net.SplitHostPort(e.client.Server)
	if err != nil {
		host = e.client.Server
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	ptr, err := reversePTR(ip.String())
	if err != nil {
		return ""
	}
	c := *e.client
	c.Debug = 0
	m, err := c.Exchange(dnsQuestion{Name: ptr, Qtype: typePTR, Qclass: classIN}, true)
	if err != nil || len(m.Answers) == 0 {
		return ""
	}
	return trimDot(m.Answers[0].Data)
}

func rcodeMessage(r uint8, name string) string {
	switch r {
	case 3:
		return fmt.Sprintf("*** %s: no records found (Non-existent domain)", name)
	case 2:
		return fmt.Sprintf("*** %s: server failed", name)
	case 5:
		return fmt.Sprintf("*** %s: query refused", name)
	case 4:
		return fmt.Sprintf("*** %s: not implemented", name)
	case 1:
		return fmt.Sprintf("*** %s: format error", name)
	}
	return fmt.Sprintf("*** %s: %s", name, rcodeText(r))
}

// Run 执行一次查询（A+AAAA 伪类型会拆成两次），并打印结果。
func (e *queryEnv) Run(name string) error {
	w := e.writer()
	original := strings.TrimSpace(name)
	qname := trimDot(original)
	if qname == "" {
		return fmt.Errorf("空的查询名称")
	}

	// IP 输入按 nslookup 行为做反向查询，并附上归属地。
	isIP := net.ParseIP(qname) != nil
	if isIP && e.qtype != typePTR {
		if ptr, err := reversePTR(qname); err == nil {
			qname = ptr
		}
	}

	types := []uint16{e.qtype}
	if e.qtype == typeAandAAAA {
		types = []uint16{typeA, typeAAAA}
	}
	qnames := []string{qname}
	if !isIP && !strings.Contains(qname, ".") {
		switch {
		case e.search && e.srchlist != "":
			qnames = nil
			for _, suffix := range strings.Split(e.srchlist, "/") {
				if s := strings.TrimSpace(suffix); s != "" {
					qnames = append(qnames, trimDot(qname)+"."+trimDot(s))
				}
			}
		case e.defname && e.domain != "":
			qnames = []string{trimDot(qname) + "." + trimDot(e.domain)}
		}
	}
	var answers, authority, extra []dnsRR
	var primary *dnsMessage
	for qi, currentName := range qnames {
		for _, typ := range types {
			q := dnsQuestion{Name: currentName, Qtype: typ, Qclass: e.class}
			m, err := e.client.Exchange(q, e.rd)
			if err != nil {
				fmt.Fprintf(w, "*** %s: 连接 DNS 服务器失败: %v\n", original, err)
				return err
			}
			if e.client.Debug > 0 {
				m.DebugDump(e.client.Debug, w)
			}
			if m.Rcode != 0 {
				if m.Rcode == 3 && qi < len(qnames)-1 {
					break // 搜索列表里的下一个域继续尝试
				}
				fmt.Fprintln(w, rcodeMessage(m.Rcode, original))
				return fmt.Errorf("rcode=%s", rcodeText(m.Rcode))
			}
			if primary == nil {
				primary = m
			}
			answers = append(answers, m.Answers...)
			authority = append(authority, m.Authority...)
			extra = append(extra, m.Extra...)
		}
		if len(answers) > 0 {
			break
		}
	}
	if primary == nil {
		return fmt.Errorf("没有收到 DNS 响应")
	}

	if primary.AA {
		fmt.Fprintln(w, "权威应答:")
	} else {
		fmt.Fprintln(w, "非权威应答:")
	}

	e.printAnswers(original, answers, authority, extra, isIP)
	return nil
}

func (e *queryEnv) geoTag(ip string) string {
	if e.noGeo || e.geo == nil || net.ParseIP(ip) == nil {
		return ""
	}
	return colored(e.geo.annotate(ip, e.verbose), e.color)
}

func (e *queryEnv) publicIPs(rrs []dnsRR) []string {
	var out []string
	seen := map[string]bool{}
	for _, rr := range rrs {
		if rr.Type != typeA && rr.Type != typeAAAA {
			continue
		}
		ip := net.ParseIP(rr.Data)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			continue
		}
		if !seen[rr.Data] {
			seen[rr.Data] = true
			out = append(out, rr.Data)
		}
	}
	return out
}

func (e *queryEnv) printAddrBlock(w *os.File, addrs []string, indent string) {
	if len(addrs) == 0 {
		return
	}
	e.geo.Warm(addrs)
	for i, a := range addrs {
		prefix := indent + "地址:    "
		if i > 0 {
			prefix = indent + "         "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, a, e.geoTag(a))
	}
}

func (e *queryEnv) printAnswers(original string, answers, authority, extra []dnsRR, isIP bool) {
	w := e.writer()
	var addrs []string
	var cnames, names []string
	for _, rr := range answers {
		switch rr.Type {
		case typeA, typeAAAA:
			addrs = append(addrs, rr.Data)
		case typeCNAME, typeDNAME, typePTR:
			cnames = append(cnames, trimDot(rr.Data))
			names = append(names, rr.Data)
		case typeNS, typeMX, typeSRV:
			names = append(names, rr.Data)
		}
	}
	if e.cdnEnabled {
		vendor := cdnFromNames(names...)
		if vendor != "" {
			fmt.Fprintf(w, "CDN:     %s\n", vendor)
		}
	}

	switch e.qtype {
	case typeA, typeAAAA, typeAandAAAA, typeANY:
		fmt.Fprintf(w, "名称:    %s\n", trimDot(original))
		for _, c := range cnames {
			fmt.Fprintf(w, "别名:    %s\n", c)
		}
		otherCount := 0
		if e.qtype == typeANY {
			for _, rr := range answers {
				if rr.Type == typeA || rr.Type == typeAAAA || rr.Type == typeCNAME || rr.Type == typeDNAME {
					continue
				}
				otherCount++
				fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", trimDot(rr.Name), rr.TTL, className(rr.Class), rr.Data)
			}
		}
		if len(addrs) == 0 {
			if otherCount == 0 {
				fmt.Fprintln(w, "地址:    (无记录)")
			}
		} else {
			e.printAddrBlock(w, addrs, "")
		}
	case typePTR:
		fmt.Fprintf(w, "%s 的 PTR 记录:\n", original)
		for _, rr := range answers {
			if rr.Type == typePTR {
				fmt.Fprintf(w, "name = %s%s\n", trimDot(rr.Data), e.geoTagIfIP(rr.Data))
			}
		}
	default:
		fmt.Fprintf(w, "%s 的 %s 记录:\n", original, typeName(e.qtype))
		for _, rr := range answers {
			fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", trimDot(rr.Name), rr.TTL, className(rr.Class), rr.Data)
		}
		if len(answers) == 0 {
			fmt.Fprintln(w, "  (无记录)")
		}
	}

	// nslookup 的附加段：把响应中额外的 A/AAAA 作为地址列出。
	var extraAddrs []string
	seen := map[string]bool{}
	for _, a := range addrs {
		seen[a] = true
	}
	for _, rr := range append(append([]dnsRR{}, extra...), authority...) {
		if (rr.Type == typeA || rr.Type == typeAAAA) && !seen[rr.Data] {
			seen[rr.Data] = true
			extraAddrs = append(extraAddrs, rr.Data)
		}
	}
	if len(extraAddrs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "其他地址:")
		e.printAddrBlock(w, extraAddrs, "")
	}
	if len(authority) > 0 && e.client.Debug > 1 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "授权段: %d 条记录\n", len(authority))
	}
}

func (e *queryEnv) geoTagIfIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return e.geoTag(s)
}
