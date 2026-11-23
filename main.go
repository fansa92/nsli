// nsli: 带 IP 归属地(nali 风格)注释的 nslookup 工具。
//
// 用法:
//
//	nsli [选项] <域名或IP>...
//	nsli                       进入交互模式
//	echo "IP 1.1.1.1" | nsli   管道模式（nali 风格）
//	nsli info|update|completion
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// version 可在构建时通过 -ldflags "-X main.version=x.y.z" 覆盖。
var version = "1.0.0"

type options struct {
	qtypeStr   string
	typeStr    string
	classStr   string
	server     string
	port       int
	timeout    time.Duration
	geoTimeout time.Duration
	retry      int
	vc         bool
	debug      int
	rd         bool
	noGeo      bool
	jsonOut    bool
	verbose    bool
	color      string
	db         string
	lang       string
	gbk        bool
	cdn        bool
	interactive bool
	showVer    bool
}

func parseFlags() options {
	var opt options
	var classStr, dbFlag, langFlag string
	var debugFlag, d2Flag, norecurse bool
	flag.StringVar(&opt.qtypeStr, "q", "A", "查询类型: A, AAAA, A+AAAA, ANY, CNAME, MX, TXT, NS, PTR, SOA, SRV, CAA 等")
	flag.StringVar(&opt.typeStr, "type", "", "查询类型（同 -q）")
	flag.StringVar(&classStr, "class", "IN", "查询类别: IN, CH, HS, ANY")
	flag.StringVar(&opt.server, "server", "", "指定 DNS 服务器, 如 8.8.8.8 或 1.1.1.1:53")
	flag.IntVar(&opt.port, "port", 53, "DNS 服务器端口")
	flag.DurationVar(&opt.timeout, "timeout", 5*time.Second, "单次 DNS 查询超时")
	flag.DurationVar(&opt.geoTimeout, "geo-timeout", 4*time.Second, "IP 归属地查询超时")
	flag.IntVar(&opt.retry, "retry", 1, "DNS 查询重试次数")
	flag.BoolVar(&opt.vc, "vc", false, "强制使用 TCP 查询")
	flag.BoolVar(&debugFlag, "debug", false, "显示调试报文")
	flag.BoolVar(&d2Flag, "d2", false, "显示详细调试报文（含 TTL）")
	flag.BoolVar(&opt.rd, "recurse", true, "请求递归查询")
	flag.BoolVar(&norecurse, "norecurse", false, "关闭递归查询")
	flag.BoolVar(&opt.noGeo, "no-geo", false, "关闭 IP 归属地查询")
	flag.BoolVar(&opt.jsonOut, "json", false, "以 JSON 格式输出结果")
	flag.BoolVar(&opt.verbose, "v", false, "显示归属地数据来源等详细信息")
	flag.StringVar(&opt.color, "color", "auto", "彩色输出: auto / always / never")
	flag.StringVar(&dbFlag, "db", "", "归属地数据源: api / qqwry(IPv4) / zxipv6(IPv6) / all(双库离线)")
	flag.StringVar(&langFlag, "lang", "", "语言: zh / en")
	flag.BoolVar(&opt.gbk, "gbk", false, "将管道输入按 GBK 解码")
	flag.BoolVar(&opt.cdn, "cdn", true, "识别 CDN 服务商")
	flag.BoolVar(&opt.interactive, "i", false, "强制进入交互模式")
	flag.BoolVar(&opt.showVer, "version", false, "显示版本号")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "nsli %s - 带 IP 归属地注释的 nslookup\n\n", version)
		fmt.Fprintf(os.Stderr, "用法:\n  %s [选项] <域名或IP>...\n  %s                    进入交互模式\n  echo \"IP 1.1.1.1\" | %s   管道模式\n  %s info|update|completion\n\n选项:\n",
			os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n  %s www.baidu.com\n  %s -q mx baidu.com\n  %s -q ptr 1.1.1.1\n  %s -q caa example.com\n  echo 'server 8.8.8.8' | %s\n",
			os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}
	flag.Parse()

	opt.classStr = classStr
	opt.db = dbFlag
	opt.lang = langFlag
	switch {
	case d2Flag:
		opt.debug = 2
	case debugFlag:
		opt.debug = 1
	}
	if norecurse {
		opt.rd = false
	}
	if opt.typeStr != "" {
		opt.qtypeStr = opt.typeStr
	}
	return opt
}

var reNameserver = regexp.MustCompile(`(?m)^\s*(?:nameserver|DNS 服务器|DNS Servers?)[^\n]*?((?:\d{1,3}\.){3}\d{1,3})`)
var reIPv4Only = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// systemDNSServers 尽力读取系统 DNS，失败时使用公共 DNS 兜底。
func systemDNSServers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		ip := net.ParseIP(s)
		if ip == nil || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, m := range reNameserver.FindAllSubmatch(b, -1) {
			add(string(m[1]))
		}
	}
	for _, args := range [][]string{
		{"interface", "ip", "show", "dnsservers"},
		{"interface", "ipv6", "show", "dnsservers"},
	} {
		cmd := exec.Command("netsh", args...)
		cmd.Stderr = nil
		if b, err := cmd.Output(); err == nil {
			for _, s := range reIPv4Only.FindAllString(string(b), -1) {
				add(s)
			}
		}
	}
	for _, s := range []string{"223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8"} {
		add(s)
	}
	return out
}

func resolveOptions(opt *options) (uint16, uint16, string, error) {
	qtype, ok := parseType(opt.qtypeStr)
	if !ok {
		return 0, 0, "", fmt.Errorf("不支持的查询类型: %s", opt.qtypeStr)
	}
	class, ok := parseClass(opt.classStr)
	if !ok {
		return 0, 0, "", fmt.Errorf("不支持的查询类别: %s", opt.classStr)
	}
	server := strings.TrimSpace(opt.server)
	if server == "" {
		servers := systemDNSServers()
		if len(servers) == 0 {
			return 0, 0, "", fmt.Errorf("无法获取系统 DNS 服务器，请用 -server 指定")
		}
		server = servers[0]
	}
	if opt.color != "auto" && opt.color != "always" && opt.color != "never" {
		return 0, 0, "", fmt.Errorf("color 只能是 auto / always / never")
	}
	return qtype, class, server, nil
}

func makeClient(server string, opt options) *dnsClient {
	return &dnsClient{
		Server: server, Timeout: opt.timeout, Retry: opt.retry,
		TCP: opt.vc, Debug: opt.debug, Out: os.Stdout,
	}
}

func makeGeo(opt options) (*GeoLookup, error) {
	db := strings.ToLower(strings.TrimSpace(opt.db))
	if db == "" {
		db = strings.ToLower(strings.TrimSpace(os.Getenv("NALI_DB_IP4")))
	}
	if db == "" {
		db = strings.ToLower(strings.TrimSpace(os.Getenv("NALI_DB_IP6")))
	}
	if db == "" {
		db = "api"
	}
	if opt.lang != "" {
		_ = os.Setenv("NALI_LANG", opt.lang)
	}
	if db == "api" || opt.noGeo {
		return NewGeoLookup(opt.geoTimeout, opt.noGeo), nil
	}

	var off4 *qqwryDB
	var off6 *zxIPv6DB
	switch db {
	case "qqwry":
		var err error
		off4, err = openQQWry(qqwryPath())
		if err != nil {
			return nil, fmt.Errorf("打开纯真库失败 (%s): %w —— 请先运行 update", qqwryPath(), err)
		}
	case "zxipv6", "zxipv6wry", "zx", "ipv6":
		var err error
		off6, err = openZXIPv6(zxIPv6Path())
		if err != nil {
			return nil, fmt.Errorf("打开 ZX IPv6 库失败 (%s): %w —— 请先运行 update", zxIPv6Path(), err)
		}
	case "all", "offline":
		var err4, err6 error
		off4, err4 = openQQWry(qqwryPath())
		off6, err6 = openZXIPv6(zxIPv6Path())
		if off4 == nil && off6 == nil {
			return nil, fmt.Errorf("没有可用的离线库: IPv4(%v), IPv6(%v) —— 请先运行 update", err4, err6)
		}
		if off4 == nil {
			fmt.Fprintf(os.Stderr, "提示: IPv4 离线库不可用，IPv4 将不显示归属地: %v\n", err4)
		}
		if off6 == nil {
			fmt.Fprintf(os.Stderr, "提示: IPv6 离线库不可用，IPv6 将不显示归属地: %v\n", err6)
		}
	default:
		return nil, fmt.Errorf("db 只能是 api / qqwry / zxipv6 / all")
	}
	return NewGeoLookupDual(opt.geoTimeout, opt.noGeo, off4, off6, false), nil
}

func main() {
	opt := parseFlags()
	if opt.showVer {
		fmt.Println("nsli", version)
		return
	}
	if opt.color == "always" {
		enableVirtualTerminal()
	}

	targets := flag.Args()
	if len(targets) > 0 {
		switch strings.ToLower(targets[0]) {
		case "help":
			flag.Usage()
			return
		case "info":
			cmdInfo()
			return
		case "update":
			db := ""
			if len(targets) > 1 {
				db = targets[1]
			}
			cmdUpdate(db)
			return
		case "completion":
			shell := ""
			if len(targets) > 1 {
				shell = targets[1]
			}
			cmdCompletion(shell)
			return
		}
	}

	qtype, class, server, err := resolveOptions(&opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "***", err)
		os.Exit(2)
	}
	geo, err := makeGeo(opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "***", err)
		os.Exit(1)
	}

	// 管道模式（nali 的核心用法）：仅在无查询目标且 stdin 非终端时启用，
	// 避免在脚本环境中把带参数的调用误判为管道而阻塞。
	if !opt.interactive && len(targets) == 0 && !isTerminal(os.Stdin) {
		var input []byte
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(os.Stdin); err == nil {
			input = buf.Bytes()
			if opt.gbk {
				input = []byte(decodeGBK(input))
			}
			if len(bytes.TrimSpace(input)) > 0 {
				processStream(bytes.NewReader(input), os.Stdout, textOptions{
					geo: geo, color: opt.color, lang: opt.lang, noGeo: opt.noGeo,
					verbose: opt.verbose, markPrivate: true,
				})
				return
			}
		}
	}

	client := makeClient(server, opt)
	if len(targets) == 0 {
		newReplState(server, opt.timeout, geo, opt.color, opt.noGeo, opt.verbose, opt.cdn, opt.lang).Run()
		return
	}

	exit := 0
	if opt.jsonOut {
		runJSON(targets, client, geo, qtype, class, server, opt)
		return
	}
	env := &queryEnv{
		client: client, qtype: qtype, class: class, rd: opt.rd,
		geo: geo, noGeo: opt.noGeo, verbose: opt.verbose,
		color: opt.color, lang: opt.lang, cdnEnabled: opt.cdn,
		serverLabel: serverLabel(opt, server),
	}
	allIP := len(targets) > 0
	for _, t := range targets {
		if net.ParseIP(trimDot(strings.TrimSpace(t))) == nil {
			allIP = false
			break
		}
	}
	if !(allIP && qtype != typePTR) {
		env.printHeader()
	}
	for i, t := range targets {
		if i > 0 {
			fmt.Println()
		}
		// IP 直查是 nali 的核心行为：直接给出归属地，不走 DNS。
		// 显式 -q ptr 时才做反向查询。
		if ip := net.ParseIP(trimDot(strings.TrimSpace(t))); ip != nil && qtype != typePTR {
			fmt.Printf("%s%s\n", ip.String(), colored(geo.annotate(ip.String(), opt.verbose), opt.color))
			continue
		}
		if err := env.Run(t); err != nil {
			exit = 1
		}
	}
	if exit != 0 {
		os.Exit(exit)
	}
}

func serverLabel(opt options, server string) string {
	if strings.TrimSpace(opt.server) == "" {
		return "系统默认 DNS (" + server + ")"
	}
	return server
}

type jsonRR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type jsonResult struct {
	Query         string    `json:"query"`
	Type          string    `json:"type"`
	Server        string    `json:"server"`
	Rcode         string    `json:"rcode,omitempty"`
	Authoritative bool      `json:"authoritative,omitempty"`
	Answers       []jsonRR  `json:"answers,omitempty"`
	Geo           []GeoInfo `json:"geo,omitempty"`
	CDN           string    `json:"cdn,omitempty"`
	Error         string    `json:"error,omitempty"`
}

func runJSON(targets []string, client *dnsClient, geo *GeoLookup, qtype, class uint16, server string, opt options) {
	var results []jsonResult
	for _, target := range targets {
		name := trimDot(strings.TrimSpace(target))
		res := jsonResult{Query: name, Type: typeName(qtype), Server: server}
		if ip := net.ParseIP(name); ip != nil && qtype != typePTR {
			res.Type = "IP"
			if g := geo.Get(name); g != nil {
				res.Geo = append(res.Geo, *g)
			}
			results = append(results, res)
			continue
		}
		qname := name
		if net.ParseIP(name) != nil {
			if ptr, err := reversePTR(name); err == nil {
				qname = ptr
			}
		}
		types := []uint16{qtype}
		if qtype == typeAandAAAA {
			types = []uint16{typeA, typeAAAA}
		}
		var names []string
		for _, typ := range types {
			m, err := client.Exchange(dnsQuestion{Name: qname, Qtype: typ, Qclass: class}, opt.rd)
			if err != nil {
				res.Error = err.Error()
				break
			}
			res.Rcode = rcodeText(m.Rcode)
			res.Authoritative = m.AA
			for _, rr := range m.Answers {
				res.Answers = append(res.Answers, jsonRR{
					Name: rr.Name, Type: typeName(rr.Type), Class: className(rr.Class),
					TTL: rr.TTL, Data: rr.Data,
				})
				if (rr.Type == typeA || rr.Type == typeAAAA) && net.ParseIP(rr.Data) != nil {
					if g := geo.Get(rr.Data); g != nil {
						res.Geo = append(res.Geo, *g)
					}
				}
				if rr.Type == typeCNAME || rr.Type == typeDNAME || rr.Type == typePTR {
					names = append(names, rr.Data)
				}
			}
		}
		if opt.cdn {
			res.CDN = cdnFromNames(names...)
		}
		results = append(results, res)
	}
	out, err := json.MarshalIndent(map[string]any{
		"server":  serverLabel(opt, server),
		"results": results,
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "*** JSON 序列化失败:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
