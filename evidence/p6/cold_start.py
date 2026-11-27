"""Cold start of the 2,000-host subnet heatmap: fresh synth DB, fresh `sshbite serve` process per measurement."""
import json
import os
import subprocess
import sys
import time
import urllib.request
import http.cookiejar
sys.path.insert(0, '/workspace')
VENV = '/workspace/.venv/bin'
D = sys.argv[1] if len(sys.argv) > 1 and __name__ == '__main__' else '/tmp/cold/run'
PW = 'correct horse battery'
os.makedirs(D, exist_ok=True)
db = f'{D}/sshbite.db'; cfg = f'{D}/sshbite.yaml'
log = []
def say(*a):
    s = ' '.join(str(x) for x in a); print(s, flush=True); log.append(s)

def fresh_db():
    for f in (db, db + '-wal', db + '-shm'):
        if os.path.exists(f):
            os.remove(f)
    open(cfg, 'w').write(f'database: {db}\nentry:\n  host: 127.0.0.1\n')
    out = subprocess.run([f'{VENV}/sshbite', '-c', cfg, 'synth', '--hosts', '2000', '--seed', '42'], capture_output=True, text=True)
    say('$ sshbite synth --hosts 2000 --seed 42 ->', out.stdout.strip().replace('\n', ' | '))
    subprocess.run([f'{VENV}/python', '-c', f'import sys; sys.path.insert(0,"/workspace"); from sshbite import db as d; from sshbite.users import add_user; c=d.connect("{db}"); add_user(c, "admin", "{PW}"); c.commit()'], check=True)

def serve(port):
    p = subprocess.Popen([f'{VENV}/sshbite', '-c', cfg, 'serve', '--port', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(200):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=1)
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.05)
            continue
        break
    return p

def http_run(port):
    p = serve(port)
    try:
        cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        req = urllib.request.Request(f'http://127.0.0.1:{port}/api/login', data=json.dumps({'username': 'admin', 'password': PW}).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        op.open(req).read()
        for i in range(4):
            t = time.perf_counter(); body = op.open(f'http://127.0.0.1:{port}/api/scans/1/heatmap?group_by=subnet').read(); ms = (time.perf_counter() - t) * 1000
            j = json.loads(body)
            say(f'  request {i + 1}: {ms:7.1f} ms wall (server compute {j["ms"]} ms), {len(j["rows"])} x {len(j["cols"])} groups, {len(body)} bytes')
    finally:
        p.terminate(); p.wait()

def browser_run(port, via_dashboard):
    from playwright.sync_api import sync_playwright
    p = serve(port)
    try:
        with sync_playwright() as pwr:
            b = pwr.chromium.launch(args=['--no-sandbox']); pg = b.new_page(viewport={'width': 1280, 'height': 800})
            base = f'http://127.0.0.1:{port}'
            if via_dashboard:
                pg.goto(base + '/login'); pg.fill('input[name=username]', 'admin'); pg.fill('input[name=password]', PW)
                pg.keyboard.press('Enter'); pg.wait_for_url(lambda u: '/login' not in u); pg.wait_for_load_state('networkidle')
                t = time.perf_counter(); pg.get_by_role('link', name='Heatmap').first.click()
            else:
                pg.goto(base + '/login')
                pg.evaluate(f"fetch('/api/login', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{username: 'admin', password: '{PW}'}})}})")
                t = time.perf_counter(); pg.goto(base + '/s/1/heatmap')
            pg.wait_for_selector('canvas.cells[data-rendered]:not([data-rendered="0"])', timeout=30000)
            ms = (time.perf_counter() - t) * 1000
            built = pg.locator('canvas.cells').get_attribute('data-rendered')
            say(f'  first render: {ms:7.1f} ms until the matrix is drawn ("built in {built} ms" in the page)')
            for i in range(3):
                pg.reload(); t = time.perf_counter()
                pg.wait_for_selector('canvas.cells[data-rendered]:not([data-rendered="0"])', timeout=30000)
                say(f'  reload {i + 1}: built in {pg.locator("canvas.cells").get_attribute("data-rendered")} ms')
            b.close()
    finally:
        p.terminate(); p.wait()

if __name__ == "__main__":
    say('# Cold start, 2,000-host subnet heatmap -', time.strftime('%Y-%m-%d %H:%M:%S'), '- commit', subprocess.run(['git', '-C', '/workspace', 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip())
    fresh_db(); say('## API, fresh process, fresh DB: GET /api/scans/1/heatmap?group_by=subnet'); http_run(8811)
    fresh_db(); say('## Browser, fresh process, fresh DB: heatmap opened as the first page after login'); browser_run(8812, False)
    fresh_db(); say('## Browser, fresh process, fresh DB: login -> Dashboard -> click Heatmap'); browser_run(8813, True)
    say('## Browser: UI started on an empty DB, then synth writes the scan while it runs, then login -> heatmap')
    for f in (db, db + '-wal', db + '-shm'):
        if os.path.exists(f):
            os.remove(f)
    open(cfg, 'w').write(f'database: {db}\nentry:\n  host: 127.0.0.1\n')
    subprocess.run([f'{VENV}/python', '-c', f'import sys; sys.path.insert(0,"/workspace"); from sshbite import db as d; from sshbite.users import add_user; c=d.connect("{db}"); add_user(c, "admin", "{PW}"); c.commit()'], check=True)
    _serve = serve
    def serve(port):
        p = _serve(port)
        out = subprocess.run([f'{VENV}/sshbite', '-c', cfg, 'synth', '--hosts', '2000', '--seed', '42'], capture_output=True, text=True)
        say('$ sshbite synth --hosts 2000 --seed 42 (UI already running) ->', out.stdout.strip().splitlines()[0])
        return p
    browser_run(8815, False)
    open(f'{D}/timings.txt', 'w').write('\n'.join(log) + '\n')
