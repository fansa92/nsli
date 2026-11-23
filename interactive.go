package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// replState 保存 nslookup 交互式会话的全部 set 选项。
type replState struct {
	server        string
	initialServer string
	rootServer    string
	qtype         uint16
	class         uint16
	rd            bool
	defname       bool
	search        bool
	vc            bool
	debug         int
	msxfr         bool
	ixfrver       string
	domain        string
	srchlist      string
	retry         int
	timeout       time.Duration
	color         string
	geo           *GeoLookup
	noGeo         bool
	verbose       bool
	cdn           bool
	lang          string
}

func newReplState(server string, timeout time.Duration, geo *GeoLookup, color string, noGeo, verbose, cdn bool, lang string) *replState {
	return &replState{
		server: server, initialServer: server, rootServer: server,
		qtype: typeA, class: classIN, rd: true, defname: true, search: false,
		timeout: timeout, retry: 1, color: color, geo: geo,
		noGeo: noGeo, verbose: verbose, cdn: cdn, lang: lang,
	}
}

func (s *replState) env() *queryEnv {
	return &queryEnv{
		client: &dnsClient{
			Server: s.server, Timeout: s.timeout, Retry: s.retry,
			TCP: s.vc, Debug: s.debug, Out: os.Stdout,
		},
		qtype: s.qtype, class: s.class, rd: s.rd,
		geo: s.geo, noGeo: s.noGeo, verbose: s.verbose,
		color: s.color, lang: s.lang, cdnEnabled: s.cdn,
		serverLabel: s.server,
		defname: s.defname, search: s.search, domain: s.domain, srchlist: s.srchlist,
	}
}

const replHelp = `命令:
  NAME             - 显示主机的域名信息（默认服务器）
  NAME1 NAME2      - 同上，但使用 NAME2 作为 DNS 服务器
  help or ?        - 显示帮助信息
  set OPTION       - 设置选项
    all                 - 打印所有选项、当前根服务器和超时信息
    [no]debug           - 打印调试信息
    [no]d2              - 打印详细的调试信息
    [no]defname         - 在每个查询后附加域名
    [no]recurse         - 查询子域的递归应答
    [no]search          - 使用域搜索列表
    [no]vc              - 始终使用 TCP 连接
    domain=NAME         - 将默认域名设为 NAME
    srchlist=N1[/N2/.../N6] - 设置域名和搜索列表
    root=NAME           - 设置根服务器为 NAME
    retry=X             - 将重试次数设为 X
    timeout=X           - 将初始超时间隔设为 X (秒)
    type=X              - 设置查询类型 (A, AAAA, A+AAAA, ANY, CNAME, MX, NS, PTR, SOA, SRV, CAA, TXT 等)
    querytype=X         - 与 type 相同
    class=X             - 设置查询类别 (IN, ANY, CH, HS)
    [no]msxfr           - 使用 MS 快速区域传送
    ixfrver=X           - 设置 IXFR 版本号
  server NAME      - 将默认服务器设为 NAME（使用当前默认服务器解析）
  lserver NAME     - 将默认服务器设为 NAME（使用初始服务器解析）
  root             - 将默认服务器重置为根服务器
  ls [opt] DOMAIN [> FILE] - 列出 DOMAIN 中的地址 (选项: -a -d -t TYPE)
  view FILE        - 查看 'ls' 输出文件
  exit             - 退出
`

func (s *replState) printAll() {
	fmt.Printf("默认服务器:  %s\n", s.server)
	fmt.Printf("初始服务器:  %s\n", s.initialServer)
	fmt.Printf("根服务器:    %s\n", s.rootServer)
	fmt.Printf("查询类型:    %s\n", typeName(s.qtype))
	fmt.Printf("查询类别:    %s\n", className(s.class))
	fmt.Printf("超时(秒):    %g\n", s.timeout.Seconds())
	fmt.Printf("重试次数:    %d\n", s.retry)
	fmt.Printf("选项:        %s%s%s%s%s%s\n",
		map[bool]string{true: "debug ", false: ""}[s.debug > 0],
		map[bool]string{true: "d2 ", false: ""}[s.debug > 1],
		map[bool]string{true: "defname ", false: ""}[s.defname],
		map[bool]string{true: "recurse ", false: ""}[s.rd],
		map[bool]string{true: "search ", false: ""}[s.search],
		map[bool]string{true: "vc ", false: ""}[s.vc])
	if s.domain != "" {
		fmt.Printf("域:          %s\n", s.domain)
	}
	if s.srchlist != "" {
		fmt.Printf("搜索列表:    %s\n", s.srchlist)
	}
	if s.ixfrver != "" {
		fmt.Printf("ixfrver:     %s\n", s.ixfrver)
	}
}

func (s *replState) applySet(rest string) {
	line := strings.TrimSpace(rest)
	if line == "" {
		s.printAll()
		return
	}
	lower := strings.ToLower(line)
	switch {
	case lower == "all":
		s.printAll()
	case lower == "debug":
		s.debug = 1
	case lower == "nodebug":
		s.debug = 0
	case lower == "d2":
		s.debug = 2
	case lower == "nod2":
		s.debug = 0
	case lower == "defname":
		s.defname = true
	case lower == "nodefname":
		s.defname = false
	case lower == "recurse":
		s.rd = true
	case lower == "norecurse":
		s.rd = false
	case lower == "search":
		s.search = true
	case lower == "nosearch":
		s.search = false
	case lower == "vc":
		s.vc = true
	case lower == "novc":
		s.vc = false
	case lower == "msxfr":
		s.msxfr = true
	case lower == "nomsxfr":
		s.msxfr = false
	case strings.HasPrefix(lower, "domain="):
		s.domain = strings.TrimSpace(rest[len("domain="):])
	case strings.HasPrefix(lower, "srchlist="):
		s.srchlist = strings.TrimSpace(rest[len("srchlist="):])
	case strings.HasPrefix(lower, "root="):
		s.rootServer = strings.TrimSpace(rest[len("root="):])
	case strings.HasPrefix(lower, "retry="):
		if n, err := strconv.Atoi(strings.TrimSpace(rest[len("retry="):])); err == nil && n >= 0 {
			s.retry = n
		} else {
			fmt.Println("*** 无效的 retry 值")
		}
	case strings.HasPrefix(lower, "timeout="):
		v := strings.TrimSpace(rest[len("timeout="):])
		if d, err := time.ParseDuration(v); err == nil {
			s.timeout = d
		} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.timeout = time.Duration(n) * time.Second
		} else {
			fmt.Println("*** 无效的 timeout 值")
		}
	case strings.HasPrefix(lower, "type="), strings.HasPrefix(lower, "querytype="):
		v := strings.TrimSpace(line[strings.Index(line, "=")+1:])
		if t, ok := parseType(v); ok {
			s.qtype = t
		} else {
			fmt.Println("*** 无效的查询类型:", v)
		}
	case strings.HasPrefix(lower, "class="):
		v := strings.TrimSpace(rest[len("class="):])
		if c, ok := parseClass(v); ok {
			s.class = c
		} else {
			fmt.Println("*** 无效的查询类别:", v)
		}
	case strings.HasPrefix(lower, "ixfrver="):
		s.ixfrver = strings.TrimSpace(rest[len("ixfrver="):])
	default:
		fmt.Println("*** 未知选项:", line)
	}
}

func (s *replState) doLS(args string) {
	fields := strings.Fields(args)
	const lsFilterNames uint16 = 0xfff1
	var filter uint16
	var domain, outFile string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "-a":
			filter = lsFilterNames
		case f == "-d":
			filter = 0
		case f == "-t" || f == "-T":
			if i+1 < len(fields) {
				i++
				if t, ok := parseType(fields[i]); ok {
					filter = t
				}
			}
		case strings.HasPrefix(f, "-t") && len(f) > 2:
			if t, ok := parseType(f[2:]); ok {
				filter = t
			}
		case f == ">":
			if i+1 < len(fields) {
				i++
				outFile = fields[i]
			}
		case strings.HasPrefix(f, ">"):
			outFile = f[1:]
		default:
			if domain == "" {
				domain = f
			} else if outFile == "" {
				outFile = f
			}
		}
	}
	if domain == "" {
		fmt.Println("*** 用法: ls [-a|-d|-t TYPE] DOMAIN [> FILE]")
		return
	}
	client := s.env().client
	rrs, err := client.AXFR(domain, s.class)
	if err != nil {
		fmt.Printf("*** %s: %v\n", domain, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s 的区域传送结果 (%d 条记录):\n", domain, len(rrs))
	for _, rr := range rrs {
		show := filter == 0 || rr.Type == filter ||
			(filter == lsFilterNames && (rr.Type == typeA || rr.Type == typeCNAME || rr.Type == typePTR || rr.Type == typeNS))
		if show {
			fmt.Fprintf(&b, "  %s  %d  %s  %s\n", rr.Name, rr.TTL, typeName(rr.Type), rr.Data)
		}
	}
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(b.String()), 0o644); err != nil {
			fmt.Printf("*** 写入 %s 失败: %v\n", outFile, err)
		} else {
			fmt.Printf("已写入 %s\n", outFile)
		}
		return
	}
	fmt.Print(b.String())
}

func (s *replState) doView(file string) {
	b, err := os.ReadFile(strings.TrimSpace(file))
	if err != nil {
		fmt.Printf("*** 无法读取 %s: %v\n", file, err)
		return
	}
	fmt.Print(string(b))
}

// Run 启动交互会话。
func (s *replState) Run() {
	fmt.Println(" nsli 交互模式 - 输入 help 查看命令, exit 退出")
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !sc.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case lower == "exit" || lower == "quit":
			return
		case lower == "help" || lower == "?":
			fmt.Print(replHelp)
		case lower == "set" || strings.HasPrefix(lower, "set "):
			s.applySet(strings.TrimSpace(line[3:]))
		case lower == "server" || strings.HasPrefix(lower, "server "):
			s.setServer(strings.TrimSpace(line[6:]), false)
		case lower == "lserver" || strings.HasPrefix(lower, "lserver "):
			s.setServer(strings.TrimSpace(line[7:]), true)
		case lower == "root":
			s.server = s.rootServer
			fmt.Println("默认服务器已重置为:", s.server)
		case lower == "ls" || strings.HasPrefix(lower, "ls "):
			s.doLS(strings.TrimSpace(line[2:]))
		case lower == "view" || strings.HasPrefix(lower, "view "):
			s.doView(strings.TrimSpace(line[4:]))
		default:
			s.queryLine(line)
		}
	}
}

func (s *replState) setServer(value string, useInitial bool) {
	if value == "" {
		fmt.Println("*** 请指定服务器名称")
		return
	}
	base := s.server
	if useInitial {
		base = s.initialServer
	}
	c := &dnsClient{Server: base, Timeout: s.timeout, Retry: s.retry, TCP: s.vc}
	if ip := net.ParseIP(value); ip == nil {
		m, err := c.Exchange(dnsQuestion{Name: trimDot(value), Qtype: typeA, Qclass: classIN}, true)
		if err != nil || len(m.Answers) == 0 {
			fmt.Printf("*** 无法解析服务器 %s\n", value)
			return
		}
		value = m.Answers[0].Data
	}
	if _, err := normalizeServer(value, 53); err != nil {
		fmt.Printf("*** 无效的服务器 %s\n", value)
		return
	}
	s.server = value
	e := s.env()
	e.printHeader()
}

func (s *replState) queryLine(line string) {
	fields := strings.Fields(line)
	name := fields[0]
	env := s.env()
	if len(fields) > 1 {
		server := fields[1]
		if ip := net.ParseIP(server); ip != nil {
			env.client.Server = server
		} else if m, err := env.client.Exchange(dnsQuestion{Name: trimDot(server), Qtype: typeA, Qclass: classIN}, true); err == nil && len(m.Answers) > 0 {
			env.client.Server = m.Answers[0].Data
		} else {
			fmt.Printf("*** 无法解析服务器 %s\n", server)
			return
		}
		env.serverLabel = env.client.Server
	}
	// IP 直查时同时给出 nali 风格归属地。
	if ip := net.ParseIP(name); ip != nil && s.geo != nil && !s.noGeo {
		fmt.Printf("%s%s\n", ip.String(), colored(s.geo.annotate(ip.String(), s.verbose), s.color))
	}
	env.printHeader()
	if err := env.Run(name); err != nil {
		_ = err
	}
}

