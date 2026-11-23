package main

// 纯标准库实现的 DNS 报文编解码与 UDP/TCP 交换，取代 net.Resolver 的封装层。
// 这样可以支持任意 RR 类型、class、RD 位、TTL、权威标志、debug 报文与 AXFR。

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// DNS RR type.
const (
	typeA         uint16 = 1
	typeNS        uint16 = 2
	typeCNAME     uint16 = 5
	typeSOA       uint16 = 6
	typePTR       uint16 = 12
	typeHINFO     uint16 = 13
	typeMX        uint16 = 15
	typeTXT       uint16 = 16
	typeRP        uint16 = 17
	typeAFSDB     uint16 = 18
	typeRT        uint16 = 21
	typeNSAP      uint16 = 22
	typeSIG       uint16 = 24
	typeKEY       uint16 = 25
	typePX        uint16 = 26
	typeSRV       uint16 = 33
	typeNAPTR     uint16 = 35
	typeKX        uint16 = 36
	typeCERT      uint16 = 37
	typeDNAME     uint16 = 39
	typeOPT       uint16 = 41
	typeDS        uint16 = 43
	typeSSHFP     uint16 = 44
	typeIPSECKEY  uint16 = 45
	typeRRSIG     uint16 = 46
	typeNSEC      uint16 = 47
	typeDNSKEY    uint16 = 48
	typeDHCID     uint16 = 49
	typeNSEC3     uint16 = 50
	typeNSEC3PARAM uint16 = 51
	typeTLSA      uint16 = 52
	typeSPF       uint16 = 99
	typeAAAA      uint16 = 28
	typeSVCB      uint16 = 64
	typeHTTPS     uint16 = 65
	typeCAA       uint16 = 257
	typeANY       uint16 = 255
	typeAXFR      uint16 = 252
	typeIXFR      uint16 = 251
	// 伪类型：Windows nslookup 的 A+AAAA。
	typeAandAAAA uint16 = 0xfffe
)

// DNS class.
const (
	classIN  uint16 = 1
	classCS  uint16 = 2
	classCH  uint16 = 3
	classHS  uint16 = 4
	classANY uint16 = 255
)

var typeNames = map[uint16]string{
	typeA: "A", typeNS: "NS", typeCNAME: "CNAME", typeSOA: "SOA", typePTR: "PTR",
	typeHINFO: "HINFO", typeMX: "MX", typeTXT: "TXT", typeRP: "RP", typeAFSDB: "AFSDB",
	typeRT: "RT", typeNSAP: "NSAP", typeSIG: "SIG", typeKEY: "KEY", typePX: "PX",
	typeSRV: "SRV", typeNAPTR: "NAPTR", typeKX: "KX", typeCERT: "CERT", typeDNAME: "DNAME",
	typeOPT: "OPT", typeDS: "DS", typeSSHFP: "SSHFP", typeIPSECKEY: "IPSECKEY",
	typeRRSIG: "RRSIG", typeNSEC: "NSEC", typeDNSKEY: "DNSKEY", typeDHCID: "DHCID",
	typeNSEC3: "NSEC3", typeNSEC3PARAM: "NSEC3PARAM", typeTLSA: "TLSA", typeSPF: "SPF",
	typeAAAA: "AAAA", typeSVCB: "SVCB", typeHTTPS: "HTTPS", typeCAA: "CAA",
	typeANY: "ANY", typeAXFR: "AXFR", typeIXFR: "IXFR", typeAandAAAA: "A+AAAA",
}

var classNames = map[uint16]string{
	classIN: "IN", classCS: "CS", classCH: "CH", classHS: "HS", classANY: "ANY",
}

// parseType 把 "MX" / "15" / "a+aaaa" 之类的输入解析为类型值。
func parseType(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "A+AAAA" || s == "A+AAAAA" {
		return typeAandAAAA, true
	}
	for t, n := range typeNames {
		if n == s {
			return t, true
		}
	}
	if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 65535 {
		return uint16(v), true
	}
	return 0, false
}

func typeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// isSupportedType 严格按大小写检查官方类型名（供旧接口与测试使用）。
func isSupportedType(t string) bool {
	for typ, name := range typeNames {
		if name == t && typ != typeAXFR && typ != typeIXFR {
			return true
		}
	}
	return false
}

func parseClass(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	for c, n := range classNames {
		if n == s {
			return c, true
		}
	}
	if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 65535 {
		return uint16(v), true
	}
	return 0, false
}

func className(c uint16) string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func rcodeText(r uint8) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

type dnsQuestion struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

type dnsMessage struct {
	ID        uint16
	QR        bool
	Opcode    uint8
	AA        bool
	TC        bool
	RD        bool
	RA        bool
	Rcode     uint8
	Questions []dnsQuestion
	Answers   []dnsRR
	Authority []dnsRR
	Extra     []dnsRR
}

// encodeName 编码域名为 DNS 线格式（带根点）。
func encodeName(name string) ([]byte, error) {
	name = trimDot(strings.TrimSpace(name))
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("域名标签过长: %s", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// decodeName 解码域名，支持 DNS 压缩指针。
func decodeName(msg []byte, off int, depth int) (string, int, error) {
	if depth > 16 {
		return "", 0, errors.New("域名压缩指针循环")
	}
	var labels []string
	pos := off
	jumped := false
	end := 0
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("域名截断")
		}
		l := int(msg[pos])
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", 0, errors.New("压缩指针截断")
			}
			ptr := int(msg[pos]&0x3f)<<8 | int(msg[pos+1])
			if !jumped {
				end = pos + 2
				jumped = true
			}
			sub, _, err := decodeName(msg, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if sub != "" && sub != "." {
				labels = append(labels, sub)
			}
			break
		}
		pos++
		if l == 0 {
			if !jumped {
				end = pos
			}
			break
		}
		if l > 63 || pos+l > len(msg) {
			return "", 0, errors.New("非法域名标签")
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
	}
	if len(labels) == 0 {
		return ".", end, nil
	}
	return strings.Join(labels, "."), end, nil
}

func readCharString(b []byte) (string, int, error) {
	if len(b) == 0 {
		return "", 0, errors.New("空字符串")
	}
	n := int(b[0])
	if n+1 > len(b) {
		return "", 0, errors.New("字符串截断")
	}
	return string(b[1 : n+1]), n + 1, nil
}

// rdataText 把 RDATA 按类型渲染为可读文本。
func rdataText(typ uint16, b []byte) (string, error) {
	switch typ {
	case typeA:
		if len(b) != 4 {
			return "", errors.New("A 记录长度错误")
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String(), nil
	case typeAAAA:
		if len(b) != 16 {
			return "", errors.New("AAAA 记录长度错误")
		}
		return net.IP(b).String(), nil
	case typeNS, typeCNAME, typePTR, typeDNAME:
		n, _, err := decodeName(b, 0, 0)
		return n, err
	case typeMX:
		if len(b) < 3 {
			return "", errors.New("MX 记录长度错误")
		}
		pref := binary.BigEndian.Uint16(b)
		host, _, err := decodeName(b, 2, 0)
		return fmt.Sprintf("%d %s", pref, host), err
	case typeTXT, typeSPF:
		var parts []string
		for i := 0; i < len(b); {
			s, n, err := readCharString(b[i:])
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
			i += n
		}
		return strings.Join(parts, " "), nil
	case typeSOA:
		mname, pos, err := decodeName(b, 0, 0)
		if err != nil {
			return "", err
		}
		rname, pos, err := decodeName(b, pos, 0)
		if err != nil {
			return "", err
		}
		if pos+20 > len(b) {
			return "", errors.New("SOA 记录长度错误")
		}
		serial := binary.BigEndian.Uint32(b[pos : pos+4])
		refresh := binary.BigEndian.Uint32(b[pos+4 : pos+8])
		retry := binary.BigEndian.Uint32(b[pos+8 : pos+12])
		expire := binary.BigEndian.Uint32(b[pos+12 : pos+16])
		minttl := binary.BigEndian.Uint32(b[pos+16 : pos+20])
		return fmt.Sprintf("%s %s ( serial=%d refresh=%d retry=%d expire=%d minimum=%d )",
			mname, rname, serial, refresh, retry, expire, minttl), nil
	case typeSRV:
		if len(b) < 7 {
			return "", errors.New("SRV 记录长度错误")
		}
		pri := binary.BigEndian.Uint16(b)
		weight := binary.BigEndian.Uint16(b[2:])
		port := binary.BigEndian.Uint16(b[4:])
		target, _, err := decodeName(b, 6, 0)
		return fmt.Sprintf("%d %d %d %s", pri, weight, port, target), err
	case typeCAA:
		if len(b) < 2 {
			return "", errors.New("CAA 记录长度错误")
		}
		tagLen := int(b[1])
		if 2+tagLen > len(b) {
			return "", errors.New("CAA 记录长度错误")
		}
		return fmt.Sprintf("%d %s \"%s\"", b[0], string(b[2:2+tagLen]), string(b[2+tagLen:])), nil
	case typeHINFO:
		cpu, n, err := readCharString(b)
		if err != nil {
			return "", err
		}
		os, _, err := readCharString(b[n:])
		return fmt.Sprintf("\"%s\" \"%s\"", cpu, os), err
	case typeNAPTR:
		if len(b) < 4 {
			return "", errors.New("NAPTR 记录长度错误")
		}
		order := binary.BigEndian.Uint16(b)
		pref := binary.BigEndian.Uint16(b[2:])
		pos := 4
		var strs []string
		for i := 0; i < 3; i++ {
			s, n, err := readCharString(b[pos:])
			if err != nil {
				return "", err
			}
			strs = append(strs, s)
			pos += n
		}
		rep, _, err := decodeName(b, pos, 0)
		return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s", order, pref,
			strs[0], strs[1], strs[2], rep), err
	case typeDS:
		if len(b) < 4 {
			return "", errors.New("DS 记录长度错误")
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b), b[2], b[3],
			strings.ToUpper(hex.EncodeToString(b[4:]))), nil
	case typeDNSKEY:
		if len(b) < 4 {
			return "", errors.New("DNSKEY 记录长度错误")
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b), b[2], b[3],
			base64.StdEncoding.EncodeToString(b[4:])), nil
	case typeTLSA:
		if len(b) < 4 {
			return "", errors.New("TLSA 记录长度错误")
		}
		return fmt.Sprintf("%d %d %d %s", b[0], b[1], b[2],
			strings.ToUpper(hex.EncodeToString(b[3:]))), nil
	case typeSSHFP:
		if len(b) < 3 {
			return "", errors.New("SSHFP 记录长度错误")
		}
		return fmt.Sprintf("%d %d %s", b[0], b[1],
			strings.ToUpper(hex.EncodeToString(b[2:]))), nil
	case typeOPT:
		return fmt.Sprintf("UDP payload=%d extended-rcode=%d",
			binary.BigEndian.Uint16(b), b[2]), nil
	case typeRP:
		mbox, pos, err := decodeName(b, 0, 0)
		if err != nil {
			return "", err
		}
		txt, _, err := decodeName(b, pos, 0)
		return mbox + " " + txt, err
	}
	return "\\# " + strconv.Itoa(len(b)) + " " + strings.ToUpper(hex.EncodeToString(b)), nil
}

func parseRR(msg []byte, off int) (dnsRR, int, error) {
	var rr dnsRR
	name, pos, err := decodeName(msg, off, 0)
	if err != nil {
		return rr, 0, err
	}
	if pos+10 > len(msg) {
		return rr, 0, errors.New("RR 头部截断")
	}
	rr.Name = name
	rr.Type = binary.BigEndian.Uint16(msg[pos : pos+2])
	rr.Class = binary.BigEndian.Uint16(msg[pos+2 : pos+4])
	rr.TTL = binary.BigEndian.Uint32(msg[pos+4 : pos+8])
	rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
	pos += 10
	if rdlen < 0 || pos+rdlen > len(msg) {
		return rr, 0, errors.New("RR 数据截断")
	}
	rr.Data, err = rdataText(rr.Type, msg[pos:pos+rdlen])
	return rr, pos + rdlen, err
}

func parseDNSMessage(buf []byte) (*dnsMessage, error) {
	if len(buf) < 12 {
		return nil, errors.New("DNS 报文过短")
	}
	m := &dnsMessage{}
	m.ID = binary.BigEndian.Uint16(buf)
	flags := binary.BigEndian.Uint16(buf[2:])
	m.QR = flags&0x8000 != 0
	m.Opcode = uint8((flags >> 11) & 0xf)
	m.AA = flags&0x0400 != 0
	m.TC = flags&0x0200 != 0
	m.RD = flags&0x0100 != 0
	m.RA = flags&0x0080 != 0
	m.Rcode = uint8(flags & 0xf)
	qd := int(binary.BigEndian.Uint16(buf[4:]))
	an := int(binary.BigEndian.Uint16(buf[6:]))
	ns := int(binary.BigEndian.Uint16(buf[8:]))
	ar := int(binary.BigEndian.Uint16(buf[10:]))
	pos := 12
	for i := 0; i < qd; i++ {
		name, p, err := decodeName(buf, pos, 0)
		if err != nil {
			return nil, err
		}
		if p+4 > len(buf) {
			return nil, errors.New("问题段截断")
		}
		m.Questions = append(m.Questions, dnsQuestion{
			Name: name,
			Qtype: binary.BigEndian.Uint16(buf[p : p+2]),
			Qclass: binary.BigEndian.Uint16(buf[p+2 : p+4]),
		})
		pos = p + 4
	}
	readRRs := func(n int) ([]dnsRR, error) {
		var out []dnsRR
		for i := 0; i < n; i++ {
			rr, p, err := parseRR(buf, pos)
			if err != nil {
				return nil, err
			}
			out = append(out, rr)
			pos = p
		}
		return out, nil
	}
	var err error
	if m.Answers, err = readRRs(an); err != nil {
		return nil, err
	}
	if m.Authority, err = readRRs(ns); err != nil {
		return nil, err
	}
	if m.Extra, err = readRRs(ar); err != nil {
		return nil, err
	}
	return m, nil
}

func buildQuery(q dnsQuestion, rd bool) []byte {
	id := uint16(rand.Uint32())
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf, id)
	var flags uint16 = 0x0100
	if rd {
		flags |= 0x0100
	} else {
		flags &^= 0x0100
	}
	binary.BigEndian.PutUint16(buf[2:], flags)
	binary.BigEndian.PutUint16(buf[4:], 1)
	name, _ := encodeName(q.Name)
	buf = append(buf, name...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[:2], q.Qtype)
	binary.BigEndian.PutUint16(tail[2:], q.Qclass)
	return append(buf, tail[:]...)
}

// normalizeServer 给裸 IP / 域名补默认 DNS 端口。
func normalizeServer(server string, port int) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", errors.New("DNS 服务器为空")
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	if strings.Contains(server, ":") && net.ParseIP(server) != nil {
		return net.JoinHostPort(server, strconv.Itoa(port)), nil
	}
	if port == 0 || port == 53 {
		return net.JoinHostPort(server, "53"), nil
	}
	return net.JoinHostPort(server, strconv.Itoa(port)), nil
}

type dnsClient struct {
	Server  string
	Timeout time.Duration
	Retry   int
	TCP     bool
	Debug   int
	Out     io.Writer
}

func (c *dnsClient) out() io.Writer {
	if c.Out != nil {
		return c.Out
	}
	return os.Stdout
}

func (c *dnsClient) printDebug(format string, args ...any) {
	if c.Debug > 0 {
		fmt.Fprintf(c.out(), format, args...)
	}
}

func (c *dnsClient) Exchange(q dnsQuestion, rd bool) (*dnsMessage, error) {
	srv, err := normalizeServer(c.Server, 53)
	if err != nil {
		return nil, err
	}
	req := buildQuery(q, rd)
	if c.Debug > 0 {
		fmt.Fprintf(c.out(), "\n>>> 发送查询: %s  type=%s  class=%s  server=%s (%s)\n",
			q.Name, typeName(q.Qtype), className(q.Qclass), srv, map[bool]string{true: "TCP", false: "UDP"}[c.TCP])
	}
	var lastErr error
	attempts := c.Retry + 1
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		msg, err := c.exchangeOnce(srv, req, q, rd)
		if err == nil {
			return msg, nil
		}
		lastErr = err
		if c.Debug > 0 {
			fmt.Fprintf(c.out(), ">>> 第 %d 次查询失败: %v\n", i+1, err)
		}
	}
	return nil, lastErr
}

func (c *dnsClient) exchangeOnce(srv string, req []byte, q dnsQuestion, rd bool) (*dnsMessage, error) {
	if c.TCP {
		return c.exchangeTCP(srv, req)
	}
	conn, err := net.DialTimeout("udp", srv, c.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		m, err := parseDNSMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		if m.ID != binary.BigEndian.Uint16(req) {
			continue
		}
		if m.TC {
			// 响应被截断，按 nslookup 行为自动改用 TCP 重试。
			return c.exchangeTCP(srv, req)
		}
		return m, nil
	}
}

func (c *dnsClient) exchangeTCP(srv string, req []byte) (*dnsMessage, error) {
	conn, err := net.DialTimeout("tcp", srv, c.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(req)))
	if _, err = conn.Write(append(lenBuf[:], req...)); err != nil {
		return nil, err
	}
	n, err := io.ReadFull(conn, lenBuf[:])
	if err != nil || n != 2 {
		return nil, errors.New("TCP DNS 长度字段读取失败")
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	buf := make([]byte, size)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return parseDNSMessage(buf)
}

// AXFR 使用 TCP 读取完整区域传送，直到收到结束 SOA。
func (c *dnsClient) AXFR(name string, class uint16) ([]dnsRR, error) {
	srv, err := normalizeServer(c.Server, 53)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", srv, c.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	q := dnsQuestion{Name: name, Qtype: typeAXFR, Qclass: class}
	req := buildQuery(q, true)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(req)))
	if _, err = conn.Write(append(lenBuf[:], req...)); err != nil {
		return nil, err
	}
	var out []dnsRR
	soaSeen := 0
	for {
		if _, err = io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("区域传送中断: %w", err)
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		buf := make([]byte, size)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		m, err := parseDNSMessage(buf)
		if err != nil {
			return nil, err
		}
		if m.Rcode != 0 {
			return nil, fmt.Errorf("区域传送失败: %s", rcodeText(m.Rcode))
		}
		for _, rr := range m.Answers {
			out = append(out, rr)
			if rr.Type == typeSOA {
				soaSeen++
			}
		}
		if soaSeen >= 2 {
			break
		}
	}
	return out, nil
}

// DebugDump 输出 nslookup 风格的报文明细（debug=1 简略，d2=2 含 TTL 与全部字段）。
func (m *dnsMessage) DebugDump(level int, w io.Writer) {
	fmt.Fprintf(w, "  HEADER:\n")
	flags := []string{}
	if m.QR {
		flags = append(flags, "response")
	}
	if m.AA {
		flags = append(flags, "authoritative")
	}
	if m.TC {
		flags = append(flags, "truncated")
	}
	if m.RD {
		flags = append(flags, "recursion desired")
	}
	if m.RA {
		flags = append(flags, "recursion available")
	}
	fmt.Fprintf(w, "    opcode=%s  id=%d  rcode=%s\n", opcodeName(m.Opcode), m.ID, rcodeText(m.Rcode))
	fmt.Fprintf(w, "    flags: %s\n", strings.Join(flags, ", "))
	for _, q := range m.Questions {
		fmt.Fprintf(w, "  QUESTION: %s  type=%s  class=%s\n", q.Name, typeName(q.Qtype), className(q.Qclass))
	}
	dump := func(label string, rrs []dnsRR) {
		if len(rrs) == 0 {
			return
		}
		fmt.Fprintf(w, "  %s:\n", label)
		for _, rr := range rrs {
			if level >= 2 {
				fmt.Fprintf(w, "    %s  type=%s class=%s ttl=%d  %s\n",
					rr.Name, typeName(rr.Type), className(rr.Class), rr.TTL, rr.Data)
			} else {
				fmt.Fprintf(w, "    %s  type=%s  %s\n", rr.Name, typeName(rr.Type), rr.Data)
			}
		}
	}
	dump("ANSWERS", m.Answers)
	dump("AUTHORITY", m.Authority)
	dump("ADDITIONAL", m.Extra)
}

func opcodeName(op uint8) string {
	if op == 0 {
		return "QUERY"
	}
	if op == 2 {
		return "STATUS"
	}
	return "OPCODE" + strconv.Itoa(int(op))
}

// reversePTR 把 IP 转成 in-addr.arpa / ip6.arpa 反向域名。
func reversePTR(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", fmt.Errorf("非法 IP: %s", s)
	}
	if v4 := ip.To4(); v4 != nil {
		parts := strings.Split(v4.String(), ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return strings.Join(parts, ".") + ".in-addr.arpa", nil
	}
	hexStr := strings.ReplaceAll(hex.EncodeToString(ip.To16()), ":", "")
	var parts []string
	for i := len(hexStr) - 1; i >= 0; i-- {
		parts = append(parts, string(hexStr[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa", nil
}
