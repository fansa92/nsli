package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// GeoInfo 是一个 IP 的归属地信息。
type GeoInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"`
	Source  string `json:"source,omitempty"`
}

// String 生成 nali 风格注释: "  [中国 上海 电信]"
func (g *GeoInfo) String() string {
	parts := make([]string, 0, 4)
	for _, p := range []string{g.Country, g.Region, g.City, g.ISP} {
		p = strings.TrimSpace(p)
		if p != "" && !contains(parts, p) {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "  [" + strings.Join(parts, " ") + "]"
}

// GeoLookup 支持在线 API 与离线纯真库，带缓存、并发预热与请求合并。
type GeoLookup struct {
	client   *http.Client
	disabled bool
	offline4 *qqwryDB
	offline6 *zxIPv6DB
	online   bool // true = 两族都走在线 API；false = 只走已配置的离线库
	lang     string
	mu       sync.Mutex
	cache    map[string]*GeoInfo     // 只缓存成功结果；失败不缓存，允许后续重试
	pending  map[string]chan struct{} // 同一 IP 的并发请求合并
}

func NewGeoLookup(timeout time.Duration, disabled bool) *GeoLookup {
	return NewGeoLookupDual(timeout, disabled, nil, nil, true)
}

// NewGeoLookupWithSource 构造只用纯真 IPv4 离线库的查询器。
func NewGeoLookupWithSource(timeout time.Duration, disabled bool, offline *qqwryDB) *GeoLookup {
	return NewGeoLookupDual(timeout, disabled, offline, nil, false)
}

// NewGeoLookupDual 按 IP 族选择离线库；online=false 时不访问网络。
func NewGeoLookupDual(timeout time.Duration, disabled bool, off4 *qqwryDB, off6 *zxIPv6DB, online bool) *GeoLookup {
	lang := strings.TrimSpace(os.Getenv("NALI_LANG"))
	if strings.HasPrefix(strings.ToLower(lang), "en") {
		lang = "en"
	} else {
		lang = "zh-CN"
	}
	return &GeoLookup{
		client:   &http.Client{Timeout: timeout},
		disabled: disabled,
		offline4: off4,
		offline6: off6,
		online:   online,
		lang:     lang,
		cache:    make(map[string]*GeoInfo),
		pending:  make(map[string]chan struct{}),
	}
}

// annotate 返回某个 IP 的 nali 风格注释(含来源), 查询关闭/失败时返回空串。
func (g *GeoLookup) annotate(ip string, verbose bool) string {
	if g == nil || g.disabled || net.ParseIP(ip) == nil {
		return ""
	}
	info := g.Get(ip)
	if info == nil {
		return ""
	}
	s := info.String()
	if s != "" && verbose && info.Source != "" {
		s = strings.TrimSuffix(s, "]") + ", 来源:" + info.Source + "]"
	}
	return s
}

// Get 查询(或从缓存读取)一个 IP 的归属地，失败返回 nil。
func (g *GeoLookup) Get(ip string) *GeoInfo {
	if g == nil || g.disabled {
		return nil
	}
	g.mu.Lock()
	if v, ok := g.cache[ip]; ok {
		g.mu.Unlock()
		return v
	}
	if ch, ok := g.pending[ip]; ok {
		g.mu.Unlock()
		<-ch
		g.mu.Lock()
		v := g.cache[ip]
		g.mu.Unlock()
		return v
	}
	ch := make(chan struct{})
	g.pending[ip] = ch
	g.mu.Unlock()

	var info *GeoInfo
	if g.online {
		info = queryProviders(g.client, ip, g.lang)
	} else {
		parsed := net.ParseIP(ip)
		switch {
		case parsed != nil && parsed.To4() != nil && g.offline4 != nil:
			info = g.offline4.Geo(ip)
		case parsed != nil && parsed.To4() == nil && g.offline6 != nil:
			info = g.offline6.Geo(ip)
		}
	}

	g.mu.Lock()
	if info != nil {
		g.cache[ip] = info
	}
	delete(g.pending, ip)
	close(ch)
	g.mu.Unlock()
	return info
}

// Warm 并发预热一批 IP 的归属地缓存，限制并发度以免触发免费 API 限流。
func (g *GeoLookup) Warm(ips []string) {
	if g == nil || g.disabled || len(ips) == 0 {
		return
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			g.Get(target)
		}(ip)
	}
	wg.Wait()
}

// provider 描述一个归属地查询 API: 请求地址 + 响应解析函数。
type provider struct {
	name  string
	url   func(ip string) string
	parse func(body []byte) *GeoInfo
}

// providers 依次尝试的免费归属地 API(均为免 key 的公开接口)。
func providers() []provider {
	return []provider{
		{
			name: "ip-api",
			url: func(ip string) string {
				return "http://ip-api.com/json/" + ip + "?fields=status,country,regionName,city,isp,org,query&lang=zh-CN"
			},
			parse: func(body []byte) *GeoInfo {
				var r struct {
					Status     string `json:"status"`
					Country    string `json:"country"`
					RegionName string `json:"regionName"`
					City       string `json:"city"`
					ISP        string `json:"isp"`
					Org        string `json:"org"`
				}
				if json.Unmarshal(body, &r) != nil || r.Status != "success" {
					return nil
				}
				return &GeoInfo{
					Country: r.Country, Region: r.RegionName, City: r.City,
					ISP: pickISP(r.ISP, r.Org), Source: "ip-api",
				}
			},
		},
		{
			name: "ip.sb",
			url:  func(ip string) string { return "https://api.ip.sb/geoip/" + ip },
			parse: func(body []byte) *GeoInfo {
				var r struct {
					Country      string `json:"country"`
					Region       string `json:"region"`
					City         string `json:"city"`
					ISP          string `json:"isp"`
					Organization string `json:"organization"`
				}
				if json.Unmarshal(body, &r) != nil {
					return nil
				}
				if r.Country == "" && r.City == "" {
					return nil
				}
				return &GeoInfo{
					Country: r.Country, Region: r.Region, City: r.City,
					ISP: pickISP(r.ISP, r.Organization), Source: "ip.sb",
				}
			},
		},
		{
			name: "ipwho.is",
			url:  func(ip string) string { return "https://ipwho.is/" + ip },
			parse: func(body []byte) *GeoInfo {
				var r struct {
					Success    bool   `json:"success"`
					Country    string `json:"country"`
					Region     string `json:"region"`
					City       string `json:"city"`
					Connection struct {
						ISP string `json:"isp"`
						Org string `json:"org"`
					} `json:"connection"`
				}
				if json.Unmarshal(body, &r) != nil || !r.Success {
					return nil
				}
				return &GeoInfo{
					Country: r.Country, Region: r.Region, City: r.City,
					ISP: pickISP(r.Connection.ISP, r.Connection.Org), Source: "ipwho.is",
				}
			},
		},
	}
}

// queryProviders 依次尝试各 API, 返回第一个成功的结果, 全部失败返回 nil。
func queryProviders(client *http.Client, ip, lang string) *GeoInfo {
	for _, p := range providers() {
		if info := fetchOne(client, p, ip, lang); info != nil {
			info.IP = ip
			info.Source = p.name
			return info
		}
	}
	return nil
}

func fetchOne(client *http.Client, p provider, ip, lang string) *GeoInfo {
	url := p.url(ip)
	if p.name == "ip-api" && lang != "" {
		url = strings.ReplaceAll(url, "lang=zh-CN", "lang="+lang)
	}
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "nsli/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return p.parse(body)
}

// pickISP 优先选择更像运营商的字段(跳过云厂商/CDN 的冗长名称)。
func pickISP(cands ...string) string {
	fallback := ""
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if fallback == "" {
			fallback = c
		}
		lower := strings.ToLower(c)
		if strings.Contains(lower, "cloudflare") || strings.Contains(lower, "google llc") ||
			strings.Contains(lower, "alicloud") || strings.Contains(lower, "tencent") ||
			strings.Contains(lower, "amazon") {
			continue
		}
		return shorten(c)
	}
	return shorten(fallback)
}

// shorten 截断过长的运营商名称。
func shorten(s string) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= 24 {
		return s
	}
	for _, sep := range []string{" Province", " network", " Corporation", " Ltd", " Inc", "(", " - "} {
		if i := strings.Index(s, sep); i > 0 {
			return strings.TrimSpace(s[:i])
		}
	}
	r := []rune(s)
	return string(r[:24]) + "…"
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
