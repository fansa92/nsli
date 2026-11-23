package main

import "strings"

// cdnRule 用 CNAME 后缀识别 CDN 服务商，等价于 nali 的 cdn.yml 内置版。
type cdnRule struct {
	Suffix string
	Vendor string
}

var cdnRules = []cdnRule{
	{"akamaiedge.net", "Akamai CDN"},
	{"akamaized.net", "Akamai CDN"},
	{"akamai.net", "Akamai CDN"},
	{"edgesuite.net", "Akamai CDN"},
	{"edgekey.net", "Akamai CDN"},
	{"akamaitechnologies.com", "Akamai CDN"},
	{"cloudfront.net", "AWS CloudFront"},
	{"azureedge.net", "Azure CDN"},
	{"azurefd.net", "Azure Front Door"},
	{"fastly.net", "Fastly CDN"},
	{"cloudflare.com", "Cloudflare CDN"},
	{"cloudflare.net", "Cloudflare CDN"},
	{"jsdelivr.net", "jsDelivr CDN"},
	{"bsgslb.cn", "白山云 CDN"},
	{"bbsgslb.cn", "白山云 CDN"},
	{"alikunlun.com", "阿里云 CDN"},
	{"alicdn.com", "阿里云 CDN"},
	{"tbcdn.cn", "阿里云 CDN"},
	{"aliyuncdn.com", "阿里云 CDN"},
	{"tencentcdn.net", "腾讯云 CDN"},
	{"qcloudcdn.com", "腾讯云 CDN"},
	{"myqcloud.com", "腾讯云 CDN"},
	{"qiniudns.com", "七牛云 CDN"},
	{"qiniu.com", "七牛云 CDN"},
	{"lxdns.com", "网宿 CDN"},
	{"wsdvs.com", "网宿 CDN"},
	{"51cdn.com", "网宿 CDN"},
	{"chinacache.net", "蓝汛 CDN"},
	{"upaiyun.com", "又拍云 CDN"},
	{"upyun.com", "又拍云 CDN"},
	{"360cdn.cn", "360 CDN"},
	{"qhcdn.com", "360 CDN"},
	{"hwcdns.com", "华为云 CDN"},
	{"huaweicloud.com", "华为云 CDN"},
	{"cdnetworks.com", "CDNetworks CDN"},
	{"incapdns.com", "Imperva CDN"},
	{"stackpathdns.com", "StackPath CDN"},
	{"belugacdn.com", "Beluga CDN"},
}

// cdnVendor 返回域名命中的 CDN 厂商名，未命中返回空串。
func cdnVendor(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return ""
	}
	for _, r := range cdnRules {
		if h == r.Suffix || strings.HasSuffix(h, "."+r.Suffix) {
			return r.Vendor
		}
	}
	return ""
}

// cdnFromNames 从一串 CNAME / 主机名里找出 CDN 厂商（去重，取第一个命中）。
func cdnFromNames(names ...string) string {
	seen := map[string]bool{}
	for _, n := range names {
		if v := cdnVendor(n); v != "" && !seen[v] {
			seen[v] = true
			return v
		}
	}
	return ""
}
