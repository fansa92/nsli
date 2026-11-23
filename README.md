# nsli

[![Release](https://github.com/fansa92/nsli/actions/workflows/release.yml/badge.svg)](https://github.com/fansa92/nsli/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/fansa92/nsli)](https://github.com/fansa92/nsli/releases/latest)

带 [nali](https://github.com/zu1k/nali) 风格 IP 归属地注释的 nslookup 工具，纯 Go 标准库实现，零第三方依赖。

在 DNS 查询结果上自动为公网 IP 附加 `[国家 省份 城市 运营商]` 注释；目标本身是 IP 时直接输出归属地。已支持 nslookup 的交互模式、`set` 选项、全 RR 类型、调试报文与区域传送，以及 nali 的管道处理、CDN 识别、彩色输出和离线纯真库。

## 安装

从 [Releases](https://github.com/fansa92/nsli/releases/latest) 下载对应平台的预编译二进制：

| 平台 | 架构 | 文件 |
|---|---|---|
| Windows | amd64 / arm64 | `nsli_windows_amd64.zip` / `nsli_windows_arm64.zip` |
| Linux | amd64 / arm64 / 386 | `nsli_linux_amd64.tar.gz` 等 |
| macOS | amd64 / arm64 | `nsli_darwin_amd64.tar.gz` / `nsli_darwin_arm64.tar.gz` |

每个 Release 附带 `checksums.txt`，可用于校验完整性。

## 构建

```bash
go build -o nsli.exe .
go test ./...
go vet ./...
```

发布通过 GitHub Actions 自动完成：推送 `v*` 标签即触发多架构交叉编译并创建 Release。

## 三种工作模式

```bash
# 1. 普通查询
nsli www.baidu.com
nsli -server 8.8.8.8 -q mx example.com
nsli -q ptr 1.1.1.1
nsli -q caa google.com -d2

# 2. 交互模式（无参数）
nsli
> set type=MX
> example.com
> ls -d example.com
> exit

# 3. 管道模式（nali 核心用法）
echo 'google 8.8.8.8 and lan 192.168.1.1' | nsli
dig www.gov.cn +short | nsli
```

## 选项

| 选项 | 说明 |
|---|---|
| `-q`, `-type` | 查询类型：A / AAAA / A+AAAA / ANY / CNAME / MX / TXT / NS / **PTR** / **SOA** / **SRV** / **CAA** / DS / DNSKEY / TLSA / NAPTR / HINFO / SPF 等，也接受数字 |
| `-class` | 查询类别 IN / CH / HS / ANY |
| `-server`, `-port` | 指定 DNS 服务器与端口（默认自动读取系统 DNS） |
| `-timeout`, `-retry`, `-vc` | 超时、重试次数、强制 TCP |
| `-debug`, `-d2` | 打印 DNS 报文明细（d2 含 TTL 与全部字段） |
| `-recurse`, `-norecurse` | 控制 RD 位 |
| `-no-geo`, `-geo-timeout` | 关闭归属地查询 / 归属地超时 |
| `-db` | 数据源：`api`（默认）/ `qqwry`（IPv4 离线）/ `zxipv6`（IPv6 离线）/ `all`（双库离线） |
| `-json`, `-v` | JSON 输出 / 显示数据来源 |
| `-color` | `auto` / `always` / `never` |
| `-lang` | `zh` / `en`（影响 ip-api 返回语言） |
| `-gbk` | 管道输入按 GBK 解码（Windows 有效） |
| `-cdn`, `-no-cdn` | 是否识别 CDN 服务商 |
| `-i` | 强制进入交互模式（即使 stdin 是管道） |
| `-version` | 版本号 |

## nslookup 兼容清单

| 能力 | 状态 |
|---|---|
| 非交互查询、`NAME` / `NAME1 NAME2` / `-server` | 支持 |
| 交互模式、`help`/`?`、`server`/`lserver`/`root`、`exit` | 支持 |
| `set all/debug/d2/defname/recurse/search/vc/domain/srchlist/root/retry/timeout/type/querytype/class/msxfr/ixfrver` | 支持（选项解析与状态保存） |
| `ls [-a/-d/-t TYPE] DOMAIN [> FILE]`（AXFR）、`view FILE` | 支持 |
| 全 RR 类型解析（含 TTL、class、权威标志、授权段/附加段） | 支持 |
| TCP 查询、TC 位自动切换 TCP、EDNS0 OPT 记录展示 | 支持 |
| `domain`/`srchlist`/`search` 实际参与短名查询展开 | 支持 |
| 权威/非权威应答提示、RCODE 错误规整 | 支持 |
| `msxfr` / `ixfrver` 的增量区域传送语义 | 仅保存选项，未实现 IXFR 增量传送 |
| `finger` | 未实现（本机 Windows nslookup 的 help 中亦无此命令） |

## nali 兼容清单

| 能力 | 状态 |
|---|---|
| IP 归属地注释、单/多 IP、IPv4 + IPv6 | 支持 |
| 管道 / stdin 按行处理、文本中就地插入注释 | 支持 |
| 交互式查询 | 支持（与 nslookup 交互模式合并） |
| 与 dig / nslookup / 任意程序组合 | 支持（作为管道过滤器） |
| CDN 服务商识别（38 条内置 CNAME 规则） | 支持 |
| 内网 IP 标注 `[局域网 IP]` | 支持 |
| 彩色输出 `--color`，`NO_COLOR` 自动关闭 | 支持 |
| JSON 输出（含 TTL / RCODE / ASN 之外的明细） | 支持 |
| `info` / `update` / `completion` 子命令 | 支持 |
| 多语言 `NALI_LANG` / `--gbk` | 支持（中/英；GBK 解码仅 Windows） |
| 离线数据库 | 已实现纯真 qqwry.dat（IPv4）与 ZX IPv6（`ipv6wry.db`），按 IP 族自动路由；GeoIP2 / ip2region / IPIP / DB-IP / IP2Location / IPinfo 未实现 |
| 配置文件 config.yaml | 未实现（当前通过环境变量与命令行配置） |

## 数据源

- **在线（默认）**：ip-api（中文，约 45 次/分钟）→ api.ip.sb → ipwho.is，单点失败自动切换；进程内缓存 + 并发预热 + 同 IP 请求合并。
- **离线 IPv4**：纯真 `qqwry.dat`（GBK 文本，索引小端 + 记录偏移 +4）。
- **离线 IPv6**：ZX IPv6 `ipv6wry.db`（IPDB 格式，UTF-8 文本），与 nali 默认 IPv6 库一致。
- `-db all` 同时加载两库，按 IP 版本自动选择；离线模式不访问网络。
- 环境变量：`NALI_HOME` / `NALI_DB_HOME` / `NALI_DB_FILE`（IPv4 库路径）/ `NALI_IP6_FILE`（IPv6 库路径）/ `NALI_DB_IP4` / `NALI_DB_IP6` / `NALI_LANG` / `NALI_QQWRY_URL` / `NALI_ZX_DB_URL` / `NALI_7Z`。

## 子命令

```bash
nsli info                  # 数据源、路径、环境变量
nsli update [qqwry|zxipv6|all]  # 下载离线库（不带参数更新全部）
nsli completion bash|zsh|powershell
```

## 示例输出

```console
$ nsli www.baidu.com
Server:  223.5.5.5
Address:  223.5.5.5#53 [public1.alidns.com]

非权威应答:
名称:    www.baidu.com
别名:    www.a.shifen.com
地址:    220.181.111.1  [中国 北京市 北京 IDC, China Telecommunications]

$ nsli -q cname www.gov.cn
CDN:     白山云 CDN
www.gov.cn 的 CNAME 记录:
  www.gov.cn  1800  IN  www.gov.cn.bsgslb.cn

$ echo 'google 8.8.8.8, lan 192.168.1.1' | nsli
google 8.8.8.8  [美国 弗吉尼亚州 Ashburn Google Public DNS], lan 192.168.1.1  [局域网 IP]

# 纯离线双库（IPv4 + IPv6）
$ nsli -db all 1.1.1.1 2001:4860:4860::8888
1.1.1.1  [澳大利亚 APNIC/CloudFlare公共DNS服务器]
2001:4860:4860::8888  [全球 Google Inc 服务器网段 (Anycast)]
```

## 代码结构

| 文件 | 说明 |
|---|---|
| `main.go` | CLI、系统 DNS 发现、JSON 输出、模式分发 |
| `dnsmsg.go` | 纯标准库 DNS 报文编解码、UDP/TCP、AXFR、debug dump |
| `query.go` | nslookup 风格查询编排与结果打印 |
| `interactive.go` | 交互 REPL 与 `set` 选项 |
| `textproc.go` / `cdn.go` | 管道文本处理、彩色、CDN 识别 |
| `geo.go` | 在线/离线归属地、缓存与并发预热 |
| `qqwry.go` / `zxipv6wry.go` / `gbk_*.go` | 纯真 IPv4 库、ZX IPv6 库解析，GBK 解码 |
| `nalicmd.go` | info / update / completion |
| `*_test.go` | 报文解析、RR 类型、纯真库、文本处理单元测试 |

## 说明

- 归属地来自免费公开 API，仅供日常排查参考；离线库依赖数据库更新时间。ZX IPv6 文本为 UTF-8，纯真 IPv4 为 GBK，两者解码路径不同。
- 区域传送（AXFR）需要目标 DNS 服务器授权，公共递归 DNS 通常返回 SERVFAIL。
- TCP 查询、区域传送、debug 报文等能力来自自研报文层，不依赖 `net.Resolver` 的高层封装。
