import asyncio
import json
import os
import uuid
import subprocess
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# --- Configuration & State ---
CONCURRENCY_LIMIT = 10
SCAN_TIMEOUT = 60 

# Map Dalfox shorthand types to readable labels
TYPE_MAP = {
    "R": "Reflected XSS",
    "S": "Stored XSS",
    "V": "Verified (DOM) XSS",
    "G": "Grep/Potential XSS"
}

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url):
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
            res = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(res.text, 'html.parser')
            links = [urljoin(url, a['href']).split('#')[0] for a in soup.find_all('a', href=True)]
            return [l for l in links if self.domain in urlparse(l).netloc]
        except:
            return []

    def run_dalfox(self, target_url):
        output_file = f"result_{uuid.uuid4().hex}.json"
        dalfox_path = "/snap/bin/dalfox" 
        cmd = [dalfox_path, "url", target_url, "--silence", "--no-color", "--format", "json", "-o", output_file]
        
        try:
            if not os.path.exists(dalfox_path):
                print(f"[-] Error: Dalfox not found at {dalfox_path}")
                return []

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.wait(timeout=SCAN_TIMEOUT)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), 15)
                except: pass
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    data = f.read().strip()
                    try:
                        results = json.loads(data) if data.startswith('[') else [json.loads(l) for l in data.splitlines()]
                        return results
                    except: return []
        except Exception as e:
            print(f"[-] Subprocess error: {e}")
        finally:
            if os.path.exists(output_file): os.remove(output_file)
        return []

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Analyzing: {url}")
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                # Resolve the shorthand type to a readable name
                raw_type = r.get('type', 'R')
                readable_type = TYPE_MAP.get(raw_type, f"Unknown ({raw_type})")
                
                finding = {"type": readable_type, "param": r.get('param'), "url": url}
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(f"[!] {readable_type} FOUND: Parameter '{r.get('param')}' at {url}")

    async def run(self):
        print(f"[*] Starting Rebuilt Orchestrator against {self.base_url}")
        
        to_crawl = [self.base_url]
        unique_targets = set()
        
        while to_crawl:
            current = to_crawl.pop(0)
            new_links = await self.fetch_links(current)
            for link in new_links:
                parsed = urlparse(link)
                sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                if sig not in unique_targets:
                    unique_targets.add(sig)
                    await self.queue.put(link)
                    to_crawl.append(link)

        print(f"[*] Discovery complete. Processing {self.queue.qsize()} unique structures...")

        tasks = []
        while not self.queue.empty():
            url = await self.queue.get()
            tasks.append(asyncio.create_task(self.worker(url)))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        print(f"\n[✓] Scan Complete. Total unique hits: {len(self.findings)}")

if __name__ == "__main__":
    target_input = input("Enter Target URL: ").strip()
    if not target_input.startswith("http"):
        target_input = "http://" + target_input
    orchestrator = XSSOrchestrator(target_input)
    asyncio.run(orchestrator.run())