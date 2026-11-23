package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func cmdInfo() {
	fmt.Printf("nsli %s\n\n", version)
	fmt.Println("归属地数据源:")
	fmt.Println("  api       在线: ip-api.com -> api.ip.sb -> ipwho.is (免费, 有速率限制)")
	fmt.Println("  qqwry     离线: 纯真 IPv4 数据库 (-db qqwry / all)")
	path := qqwryPath()
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("            已安装: %s\n", path)
	} else {
		fmt.Printf("            未安装: %s (运行 update qqwry 下载)\n", path)
	}
	fmt.Println("  zxipv6    离线: ZX IPv6 数据库 (-db zxipv6 / all)")
	path6 := zxIPv6Path()
	if _, err := os.Stat(path6); err == nil {
		fmt.Printf("            已安装: %s\n", path6)
	} else {
		fmt.Printf("            未安装: %s (运行 update zxipv6 下载)\n", path6)
	}
	fmt.Printf("CDN 规则:   %d 条内置规则\n", len(cdnRules))
	fmt.Printf("数据目录:   %s\n", naliHome())
	fmt.Printf("配置文件:   %s/config.yaml (可选, 当前从环境变量读取)\n", naliHome())
	fmt.Println("\n环境变量:")
	fmt.Println("  NALI_HOME       数据目录")
	fmt.Println("  NALI_DB_HOME    数据库目录")
	fmt.Println("  NALI_DB_FILE    纯真库文件路径")
	fmt.Println("  NALI_IP6_FILE   ZX IPv6 库文件路径")
	fmt.Println("  NALI_DB_IP4     IPv4 数据源: api / qqwry / all")
	fmt.Println("  NALI_DB_IP6     IPv6 数据源: api / zxipv6 / all")
	fmt.Println("  NALI_ZX_DB_URL  ZX IPv6 库 .db 直链（跳过 7z 解压）")
	fmt.Println("  NALI_7Z         7z 解压程序路径")
	fmt.Println("  NALI_LANG       zh / en")
	fmt.Println("  NO_COLOR        关闭彩色输出")
}

var qqwryURLs = []string{
	"https://gh-proxy.com/https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat",
	"https://gh-proxy.com/https://raw.githubusercontent.com/adysec/IP_database/main/qqwry/qqwry.dat",
	"https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat",
	"https://qqwry.mirror.noc.one/qqwry.dat",
}

func cmdUpdate(db string) {
	db = strings.ToLower(strings.TrimSpace(db))
	var targets []string
	switch db {
	case "", "all":
		targets = []string{"qqwry", "zxipv6"}
	case "qqwry":
		targets = []string{"qqwry"}
	case "zxipv6", "zxipv6wry", "zx", "ipv6":
		targets = []string{"zxipv6"}
	default:
		fmt.Printf("*** 不支持更新数据源: %s (支持 qqwry / zxipv6 / all)\n", db)
		return
	}
	for _, t := range targets {
		if t == "qqwry" {
			updateQQWry()
		} else {
			updateZXIPv6()
		}
	}
}

func downloadBytes(urls []string) []byte {
	client := &http.Client{Timeout: 180 * time.Second}
	for _, u := range urls {
		fmt.Printf("正在下载: %s\n", u)
		resp, err := client.Get(u)
		if err != nil {
			fmt.Printf("  失败: %v\n", err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Printf("  失败: status=%d err=%v\n", resp.StatusCode, err)
			continue
		}
		return b
	}
	return nil
}

func saveDB(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Printf("*** 创建目录失败: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Printf("*** 写入失败: %v\n", err)
		return
	}
	fmt.Printf("数据库已更新: %s (%d 字节)\n", path, len(data))
}

func updateQQWry() {
	urls := qqwryURLs
	if v := strings.TrimSpace(os.Getenv("NALI_QQWRY_URL")); v != "" {
		urls = append([]string{v}, urls...)
	}
	client := &http.Client{Timeout: 180 * time.Second}
	for _, u := range urls {
		fmt.Printf("正在下载纯真数据库: %s\n", u)
		resp, err := client.Get(u)
		if err != nil {
			fmt.Printf("  失败: %v\n", err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Printf("  失败: status=%d err=%v\n", resp.StatusCode, err)
			continue
		}
		if len(b) < 1<<20 {
			fmt.Printf("  失败: 文件过小 (%d 字节)\n", len(b))
			continue
		}
		if _, err := openQQWryBytes(b); err != nil {
			fmt.Printf("  失败: %v\n", err)
			continue
		}
		saveDB(qqwryPath(), b)
		return
	}
	fmt.Println("*** 纯真数据库所有下载地址均失败；可用 NALI_QQWRY_URL 指定镜像。")
}

const zxIPv6DownloadURL = "https://ip.zxinc.org/ip.7z"

var zxIPv6DBURLs = []string{
	"https://gh-proxy.com/https://raw.githubusercontent.com/ZX-Inc/zxipdb-python/main/data/ipv6wry.db",
	"https://raw.githubusercontent.com/ZX-Inc/zxipdb-python/main/data/ipv6wry.db",
	"https://raw.gitmirror.com/adysec/IP_database/main/ipv6wry/ipv6wry.db",
}

func find7z() string {
	if v := strings.TrimSpace(os.Getenv("NALI_7Z")); v != "" {
		return v
	}
	for _, name := range []string{"7z", "7za", "7zr"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		`C:\Program Files\7-Zip\7z.exe`,
		`C:\Program Files (x86)\7-Zip\7z.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func updateZXIPv6() {
	path := zxIPv6Path()
	var data []byte
	if v := strings.TrimSpace(os.Getenv("NALI_ZX_DB_URL")); v != "" {
		data = downloadBytes([]string{v})
	} else {
		// 优先拿已解压的 .db 直链，避免依赖 7z 与官方站点的慢速下载。
		for _, u := range zxIPv6DBURLs {
			b := downloadBytes([]string{u})
			if len(b) > 0 {
				if _, err := parseZXIPv6(b); err == nil {
					data = b
					break
				}
				fmt.Printf("  下载内容不是有效的 IPDB 数据库: %s\n", u)
			}
		}
	}
	if len(data) == 0 {
		archive := downloadBytes([]string{zxIPv6DownloadURL})
		if len(archive) > 0 {
			tmp, err := os.CreateTemp("", "nali-zx-*.7z")
			if err == nil {
				_, _ = tmp.Write(archive)
				tmp.Close()
				defer os.Remove(tmp.Name())
				if sz := find7z(); sz != "" {
					fmt.Printf("正在解压 ZX IPv6 数据库: %s\n", sz)
					out, err := exec.Command(sz, "e", "-so", tmp.Name(), "ipv6wry.db").Output()
					if err == nil {
						data = out
					} else {
						fmt.Printf("  解压失败: %v\n", err)
					}
				} else {
					fmt.Println("*** 本机未找到 7z，无法解压 ip.7z。")
				}
			}
		}
	}
	if len(data) == 0 {
		fmt.Printf("*** ZX IPv6 数据库下载失败。请手动下载 %s，解压出 ipv6wry.db 放到:\n    %s\n    或用 NALI_ZX_DB_URL 指定直接的 .db 地址，用 NALI_7Z 指定解压程序。\n",
			zxIPv6DownloadURL, path)
		return
	}
	if _, err := parseZXIPv6(data); err != nil {
		fmt.Printf("*** 下载内容不是有效的 IPDB 数据库: %v\n", err)
		return
	}
	saveDB(path, data)
}

func openQQWryBytes(b []byte) (*qqwryDB, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("文件过短")
	}
	first := binaryLE32(b[0:4])
	last := binaryLE32(b[4:8])
	if first > last || uint64(last)+7 > uint64(len(b)) {
		return nil, fmt.Errorf("索引范围无效")
	}
	return &qqwryDB{data: b, first: first, last: last}, nil
}

func binaryLE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func cmdCompletion(shell string) {
	switch strings.ToLower(shell) {
	case "bash":
		fmt.Print(`_nsli_complete() {
  COMPREPLY=( $(compgen -W "-q -type -server -timeout -retry -vc -class -debug -d2 -json -no-geo -color -db -lang -gbk -v -version info update completion help" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _nsli_complete nsli
`)
	case "zsh":
		fmt.Print(`#compdef nsli
_arguments '*: :->args' \
  '-q[查询类型]' '-type[查询类型]' '-server[DNS服务器]' '-timeout[超时]' \
  '-retry[重试]' '-vc[TCP]' '-class[查询类别]' '-debug[调试]' '-d2[详细调试]' \
  '-json[JSON输出]' '-no-geo[关闭归属地]' '-color[颜色]' '-db[数据源]' \
  '-lang[语言]' '-gbk[GBK输入]' '-v[详情]' '-version[版本]'
`)
	case "powershell", "pwsh", "":
		fmt.Print(`Register-ArgumentCompleter -Native -CommandName 'nsli' -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  @('-q','-type','-server','-timeout','-retry','-vc','-class','-debug','-d2',
    '-json','-no-geo','-color','-db','-lang','-gbk','-v','-version',
    'info','update','completion','help') |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}
`)
	default:
		fmt.Printf("*** 不支持的 shell: %s (支持 bash / zsh / powershell)\n", shell)
	}
}
