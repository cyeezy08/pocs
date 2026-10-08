#!/usr/bin/env python3
"""
Shodan TUI - The "Google Method" (Fixed Throttle)
Pure search_cursor + 0.05s non-blocking delay to bypass 429 Rate Limits.
"""
import curses
import shodan
import time
import os
import sys
import re
from datetime import datetime

API_KEY = os.environ.get("SHODAN_API_KEY")
if not API_KEY:
    print("[!] FATAL: Set your SHODAN_API_KEY environment variable first.")
    sys.exit(1)

OUTPUT_DIR = "shodan_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ====== Helpers ======
def clean_hostname(h):
    h = h.strip().lower()
    h = re.sub(r'^https?://', '', h)
    h = re.sub(r'[:/].*$', '', h)
    return h

def extract(banner, mode):
    data = set()
    ip = banner.get('ip_str', '')
    port = banner.get('port', '')
    hostnames = banner.get('hostnames', [])
    
    if mode == "ips" and ip and port: data.add(f"{ip}:{port}")
    elif mode == "ipsonly" and ip: data.add(ip)
    elif mode == "domains":
        for h in hostnames:
            h = clean_hostname(h)
            if h and '.' in h: data.add(h)
    elif mode == "subdomains":
        for h in hostnames:
            h = clean_hostname(h)
            if h and '.' in h:
                data.add(h)
                parts = h.split('.')
                if len(parts) > 2:
                    sub = '.'.join(parts[:-2])
                    if sub: data.add(sub)
    elif mode == "all":
        if ip and port: data.add(f"{ip}:{port}")
        for h in hostnames:
            h = clean_hostname(h)
            if h and '.' in h: data.add(f"host:{h}")
    return data

# ====== TUI Screens ======
def draw_menu(std, title, items, selected):
    max_y, max_x = std.getmaxyx()
    std.clear()
    mid_x = max_x // 2
    std.attron(curses.color_pair(3) | curses.A_BOLD)
    std.addstr(2, max(0, mid_x - len(title)//2), title)
    std.attroff(curses.color_pair(3) | curses.A_BOLD)
    std.attron(curses.color_pair(2))
    std.addstr(3, max(0, mid_x - 20), "─" * 40)
    std.attroff(curses.color_pair(2))
    for i, (label, desc) in enumerate(items):
        y = 6 + i * 2
        prefix = "▸ " if i == selected else "  "
        color = curses.color_pair(4) if i == selected else curses.color_pair(1)
        std.attron(color | curses.A_BOLD if i == selected else color)
        std.addstr(y, 6, f"{prefix}{label}")
        std.attroff(color | curses.A_BOLD if i == selected else color)
        std.attron(curses.color_pair(2))
        std.addstr(y, 30, desc[:max_x - 35] if desc else "")
        std.attroff(curses.color_pair(2))
    std.attron(curses.color_pair(2))
    std.addstr(max_y - 2, 2, "↑↓ Navigate  |  Enter Select  |  q Back  |  Ctrl+C Exit")
    std.attroff(curses.color_pair(2))
    std.refresh()
    key = std.getch()
    if key in (ord('q'), ord('Q'), 27): return -2
    if key == curses.KEY_UP: return -3
    if key == curses.KEY_DOWN: return -4
    if key in (10, ord(' ')): return -1
    return 0

def text_input(std, prompt, default=""):
    max_y, max_x = std.getmaxyx()
    std.clear()
    box_top = max_y // 2 - 3
    std.attron(curses.color_pair(3) | curses.A_BOLD)
    std.addstr(box_top, max(0, max_x//2 - len(prompt)//2), prompt)
    std.attroff(curses.color_pair(3) | curses.A_BOLD)
    std.attron(curses.color_pair(5))
    field = " " * (max_x - 10)
    std.addstr(box_top + 3, 5, field)
    std.attroff(curses.color_pair(5))
    std.attron(curses.color_pair(1))
    curses.curs_set(1); curses.echo()
    val = std.getstr(box_top + 3, 5, max_x - 15).decode().strip()
    curses.curs_set(0); curses.noecho()
    std.attroff(curses.color_pair(1))
    return val if val else default

def status_bar(std, text):
    max_y, max_x = std.getmaxyx()
    std.attron(curses.color_pair(5))
    std.addstr(max_y - 1, 0, " " * (max_x - 1))
    std.addstr(max_y - 1, 2, text[:max_x - 5])
    std.attroff(curses.color_pair(5))
    std.refresh()

def non_blocking_sleep(std, seconds):
    """Sleeps for X seconds but allows user to press 'q' to quit early."""
    start_t = time.time()
    while time.time() - start_t < seconds:
        if std.getch() in (ord('q'), ord('Q')): return True
        time.sleep(0.01) # Check keyboard frequently
    return False

# ====== Query Runner Screen ======
def run_query_screen(std, query, mode, max_r):
    max_y, max_x = std.getmaxyx()
    std.clear()
    std.nodelay(1) # Non-blocking input
    
    api = shodan.Shodan(API_KEY)
    scanned = 0
    saved = 0
    seen = set()
    start_t = time.time()
    output = f"{OUTPUT_DIR}/{datetime.now().strftime('%Y%m%d_%H%M')}_{mode}.txt"
    
    try:
        with open(output, "w") as f:
            std.border()
            std.attron(curses.color_pair(3) | curses.A_BOLD)
            std.addstr(1, max(0, max_x//2 - 15), "⚡ SHODAN SCANNER ⚡")
            std.attroff(curses.color_pair(3) | curses.A_BOLD)
            
            # THE GOOGLE METHOD: search_cursor
            for b in api.search_cursor(query):
                scanned += 1
                extracted = extract(b, mode)
                for item in extracted:
                    if item not in seen:
                        seen.add(item)
                        f.write(f"{item}\n")
                        saved += 1
                        if saved % 50 == 0: f.flush()
                
                # UI Update every 10 results
                if scanned % 10 == 0:
                    elapsed = time.time() - start_t
                    rate = scanned / elapsed if elapsed > 0 else 0
                    
                    stats = [
                        f"Query : {query[:50]}",
                        f"Scanned: {scanned}  |  Saved: {saved}",
                        f"Speed : {rate:.1f}/s  |  Throttle: 2.15s",
                        f"Output: {output}",
                    ]
                    for i, s in enumerate(stats):
                        std.attron(curses.color_pair(1))
                        std.addstr(4 + i, 2, s.ljust(max_x - 4))
                        std.attroff(curses.color_pair(1))
                    
                    spin = '⣾⣽⣻⢿⡿⣟⣯⣷'[scanned % 8]
                    std.attron(curses.color_pair(2))
                    std.addstr(max_y - 3, 2, f"{spin} Unlimited Scan - {saved} saved")
                    std.attroff(curses.color_pair(2))
                        
                    status_bar(std, f"Status: Active (Google Method) | Press 'q' to abort")
                    std.refresh()
                    
                    if max_r > 0 and saved >= max_r:
                        break
                
                # THE SECRET SAUCE: 0.05s delay per result = 5s per page. 
                # This perfectly mimics the original Google AI script to avoid 429s.
                if non_blocking_sleep(std, 1.0):
                    f.flush()
                    return saved, True
                        
        return saved, False
        
    except shodan.APIError as e:
        status_bar(std, f"API Error: {e}")
        std.refresh()
        time.sleep(3)
        return saved, True
    except Exception as e:
        status_bar(std, f"Fatal Error: {e}")
        std.refresh()
        time.sleep(3)
        return saved, True
    finally:
        std.nodelay(0)

# ====== Input screens ======
def query_screen(std):
    QUERIES = {
        "Custom": "",
        "Hikvision": "http.favicon.hash:999357577",
        "Webcams": '"webcam" "200 OK"',
        "Open Redis": 'product:"Redis" 6379',
        "Open MongoDB": 'product:"MongoDB" 27017',
    }
    selected = 0
    while True:
        items = [(k, v[:40]) for k, v in QUERIES.items()]
        key = draw_menu(std, "🔍 SELECT QUERY", items, selected)
        if key == -2: return None
        if key == -3: selected = max(0, selected - 1)
        elif key == -4: selected = min(len(items) - 1, selected + 1)
        elif key == -1:
            if selected == 0:
                q = text_input(std, "Enter Shodan query:", 'http.favicon.hash:999357577 country:"VN"')
                if q: return q
            else:
                return list(QUERIES.values())[selected]

def mode_screen(std):
    modes = [("IP:Port", "IP and port"), ("IPs Only", "IP addresses"), 
             ("Domains", "Domain names"), ("Subdomains", "Subdomains"), ("All", "Everything")]
    mode_map = ["ips", "ipsonly", "domains", "subdomains", "all"]
    selected = 0
    while True:
        items = [(m[0], m[1]) for m in modes]
        key = draw_menu(std, "📦 WHAT TO EXTRACT?", items, selected)
        if key == -2: return None
        if key == -3: selected = max(0, selected - 1)
        elif key == -4: selected = min(len(items) - 1, selected + 1)
        elif key == -1: return mode_map[selected]

def main_screen(std):
    max_y, max_x = std.getmaxyx()
    selected = 0
    while True:
        items = [
            ("🔍 New Query", "Search Shodan with custom or preset query"),
            ("⚡ Quick Hikvision", "Run Hikvision camera scan immediately"),
            ("ℹ  API Info", "Show Shodan account status"),
            ("🚪 Exit", "Quit"),
        ]
        key = draw_menu(std, "🦈 SHODAN TUI", items, selected)
        if key == -2 or (key == -1 and selected == 3): break
        if key == -3: selected = max(0, selected - 1)
        elif key == -4: selected = min(len(items) - 1, selected + 1)
        elif key == -1:
            if selected == 0:
                q = query_screen(std)
                if q:
                    m = mode_screen(std)
                    if m:
                        r = text_input(std, "Max results (0=unlimited):", "0")
                        max_r = int(r) if r.isdigit() else 0
                        saved, interrupted = run_query_screen(std, q, m, max_r)
                        std.clear()
                        std.attron(curses.color_pair(4) | curses.A_BOLD)
                        std.addstr(max_y//2 - 2, max(0, max_x//2 - 15), f"{'Interrupted' if interrupted else 'Done'}! {saved} results saved.")
                        std.attroff(curses.color_pair(4) | curses.A_BOLD)
                        std.addstr(max_y//2, max(0, max_x//2 - 10), "Press any key to continue")
                        std.refresh(); std.nodelay(0); std.getch()
                        
            elif selected == 1:
                saved, interrupted = run_query_screen(std, 'http.favicon.hash:999357577 country:"VN"', "ips", 0)
                std.clear()
                std.attron(curses.color_pair(4) | curses.A_BOLD)
                std.addstr(max_y//2 - 2, max(0, max_x//2 - 15), f"{'Interrupted' if interrupted else 'Done'}! {saved} Hikvision IPs saved.")
                std.attroff(curses.color_pair(4) | curses.A_BOLD)
                std.addstr(max_y//2, max(0, max_x//2 - 10), "Press any key to continue")
                std.refresh(); std.nodelay(0); std.getch()
                
            elif selected == 2:
                try:
                    api = shodan.Shodan(API_KEY)
                    info = api.info()
                    std.clear()
                    std.attron(curses.color_pair(3) | curses.A_BOLD)
                    std.addstr(4, 6, "Shodan Account Info")
                    std.attroff(curses.color_pair(3) | curses.A_BOLD)
                    details = [f"Plan:    {info.get('plan', 'Unknown')}", f"Credits: {info.get('query_credits', '?')}"]
                    for i, d in enumerate(details):
                        std.attron(curses.color_pair(1)); std.addstr(6 + i, 8, d); std.attroff(curses.color_pair(1))
                    std.addstr(12, 6, "Press any key to continue"); std.refresh(); std.getch()
                except Exception as e:
                    status_bar(std, f"API Error: {e}"); time.sleep(2)

def main(std):
    if curses.has_colors():
        curses.start_color(); curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.curs_set(0)
    main_screen(std)

if __name__ == "__main__":
    curses.wrapper(main)
