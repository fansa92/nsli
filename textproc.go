package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

// 用于管道输入的 IP 识别。Go 的 regexp(RE2) 不支持环视，故用宽松匹配 + ParseIP 校验。
var reIPv4Text = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var reIPv6Text = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b`)

type textOptions struct {
	geo         *GeoLookup
	color       string // auto / always / never
	lang        string
	noGeo       bool
	verbose     bool
	markPrivate bool // nali 会标注内网 IP，DNS 结果默认跳过
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colored 给注释上色；auto 只在输出是终端时生效。
func colored(s, mode string) string {
	if s == "" || mode == "never" || os.Getenv("NO_COLOR") != "" {
		return s
	}
	if mode == "auto" && !isTerminal(os.Stdout) {
		return s
	}
	return "\x1b[36m" + s + "\x1b[0m"
}

type ipMatch struct {
	start int
	end   int
	text  string
}

// findIPs 找出一行文本里的全部 IP，过滤掉 IPv6 的碎片与已带注释的部分。
func findIPs(line string) []ipMatch {
	type span struct{ a, b int }
	var spans []span
	for _, re := range []*regexp.Regexp{reIPv4Text, reIPv6Text} {
		for _, m := range re.FindAllStringIndex(line, -1) {
			spans = append(spans, span{m[0], m[1]})
		}
	}
	// 两组正则的匹配结果各自有序，但合并后必须重新排序，否则 annotateLine 会回退切片。
	sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })
	// 去掉互相重叠的匹配（保留更长的那个，通常是 IPv6）。
	for i := 0; i < len(spans); i++ {
		for j := i + 1; j < len(spans); j++ {
			if spans[j].a < spans[i].b && spans[j].b > spans[i].a {
				if spans[j].b-spans[j].a > spans[i].b-spans[i].a {
					spans[i] = spans[j]
				}
				spans = append(spans[:j], spans[j+1:]...)
				j--
			}
		}
	}
	var out []ipMatch
	for _, s := range spans {
		text := line[s.a:s.b]
		if net.ParseIP(text) == nil {
			continue
		}
		if s.b < len(line) && (line[s.b] == '[' || line[s.b] == ':' || line[s.b] == '%') {
			continue
		}
		if s.a > 0 && (line[s.a-1] == ':' || line[s.a-1] == '%') {
			continue
		}
		out = append(out, ipMatch{s.a, s.b, text})
	}
	return out
}

// annotateLine 在文本中的每个 IP 后就地插入归属地注释（nali 的管道行为）。
func annotateLine(line string, opt textOptions) string {
	if opt.geo == nil || opt.noGeo || len(line) == 0 {
		return line
	}
	matches := findIPs(line)
	if len(matches) == 0 {
		return line
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		var tag string
		ip := net.ParseIP(m.text)
		if ip == nil {
			continue
		}
		public := ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
		if !public {
			if !opt.markPrivate {
				continue
			}
			tag = "  [局域网 IP]"
			if opt.lang == "en" {
				tag = "  [private IP]"
			}
		} else {
			tag = opt.geo.annotate(m.text, opt.verbose)
		}
		if tag == "" {
			continue
		}
		b.WriteString(line[last:m.end])
		b.WriteString(colored(tag, opt.color))
		last = m.end
	}
	b.WriteString(line[last:])
	return b.String()
}

// processStream 逐行处理管道输入。
func processStream(r io.Reader, w io.Writer, opt textOptions) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if opt.geo != nil && !opt.noGeo {
			opt.geo.Warm(ipsFromLine(line))
		}
		io.WriteString(w, annotateLine(line, opt))
		io.WriteString(w, "\n")
	}
}

func ipsFromLine(line string) []string {
	var out []string
	for _, m := range findIPs(line) {
		ip := net.ParseIP(m.text)
		if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			out = append(out, m.text)
		}
	}
	return out
}
