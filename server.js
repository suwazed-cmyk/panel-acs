#!/usr/bin/env node
// =====================================================================
//  Panel ACS — monitoring ONT dari GenieACS (Node.js, tanpa dependensi)
//  - Database SQLite bawaan Node.js (node:sqlite, Node 22.13+), berkas sama dengan versi PHP
//  - Router dikenali otomatis dari IP virtual di panel utama (ACS NETMAP Panel)
//  - Tag GenieACS dipakai untuk nama pelanggan ("nama:...") dan label bebas
// =====================================================================
"use strict";
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { DatabaseSync } = require("node:sqlite");

const APP_DIR = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(APP_DIR, "data");
const DB_FILE = path.join(DATA_DIR, "panel-acs.db");
const LINK_FILE = path.join(DATA_DIR, "panel-link.json");
const PORT = parseInt(process.env.PORT, 10) || 8091;
const HOST = process.env.HOST || "127.0.0.1";
const VERSION = "3.0.0";
const RX_RAW_DAYS = 7;
const RX_PROVISION = "panel-acs-rx";
const COLLECT_MS = 15 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------------------------------------------------------------
//  Database (skema sama dengan versi PHP, ditambah tabel sesi)
// ---------------------------------------------------------------------
const db = new DatabaseSync(DB_FILE);
db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
  CREATE TABLE IF NOT EXISTS locations (dev TEXT PRIMARY KEY, lat REAL NOT NULL, lng REAL NOT NULL, updated INTEGER);
  CREATE TABLE IF NOT EXISTS rx_raw (dev TEXT NOT NULL, ts INTEGER NOT NULL, rx REAL, temp REAL, PRIMARY KEY (dev, ts)) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS rx_hour (dev TEXT NOT NULL, hour INTEGER NOT NULL, avg REAL, min REAL, max REAL, n INTEGER, PRIMARY KEY (dev, hour)) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS rx_raw_ts ON rx_raw (ts);
  CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, ts INTEGER);
  CREATE TABLE IF NOT EXISTS sessions (h TEXT PRIMARY KEY, created INTEGER, last INTEGER, ip TEXT, ua TEXT);
`);
const now = () => Math.floor(Date.now() / 1000);
function tx(fn) {
  db.exec("BEGIN");
  try {
    const r = fn();
    db.exec("COMMIT");
    return r;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
function cacheGet(k, maxAge) {
  const r = db.prepare("SELECT v, ts FROM cache WHERE k = ?").get(k);
  if (!r) return null;
  return { v: JSON.parse(r.v), fresh: now() - r.ts <= maxAge, ts: r.ts };
}
function cacheSet(k, v) {
  db.prepare("INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)").run(k, JSON.stringify(v), now());
}

// ---------------------------------------------------------------------
//  Pengaturan
// ---------------------------------------------------------------------
function panelLink() {
  try {
    const l = JSON.parse(fs.readFileSync(LINK_FILE, "utf8"));
    return l && l.url && l.key ? l : null;
  } catch (e) {
    return null;
  }
}
function defaults() {
  const l = panelLink();
  return {
    app_name: "Panel ACS",
    acs_url: l && l.nbi ? l.nbi : "http://127.0.0.1:7557",
    acs_user: "",
    acs_pass: "",
    online_minutes: 10,
    online_auto: true,
    rx_good: -23,
    rx_fair: -27,
    rx_keep_days: 90,
    rx_drop_db: 2,
    timezone: "Asia/Makassar",
    admin_user: "admin",
    admin_pass: "",
  };
}
function loadSettings() {
  const s = defaults();
  for (const r of db.prepare("SELECT k, v FROM settings").all()) {
    try {
      s[r.k] = JSON.parse(r.v);
    } catch (e) {
      // abaikan nilai rusak
    }
  }
  return s;
}
function saveSettings(patch) {
  const st = db.prepare("INSERT OR REPLACE INTO settings (k, v) VALUES (?, ?)");
  tx(() => {
    for (const [k, v] of Object.entries(patch)) st.run(k, JSON.stringify(v));
  });
}

// ---------------------------------------------------------------------
//  Password: scrypt; hash bcrypt lama (versi PHP) diverifikasi lewat php/python3 lalu diganti
// ---------------------------------------------------------------------
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(pw), salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("base64")}$${h.toString("base64")}`;
}
function runCmd(cmd, args, input) {
  return new Promise((resolve) => {
    const p = execFile(cmd, args, { timeout: 15000 }, (err, out) => resolve({ code: err ? (err.code === "ENOENT" ? -2 : 1) : 0, out: String(out || "") }));
    if (input != null) p.stdin.end(input);
  });
}
async function verifyPw(pw, hash) {
  hash = String(hash || "");
  if (hash.startsWith("scrypt$")) {
    const [, salt, h] = hash.split("$");
    const a = crypto.scryptSync(String(pw), Buffer.from(salt, "base64"), 32, { N: 16384, r: 8, p: 1 });
    const b = Buffer.from(h, "base64");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  if (/^\$2[aby]\$\d\d\$/.test(hash)) {
    // password dikirim lewat stdin supaya tidak terlihat di daftar proses
    const php = await runCmd("php", ["-r", '$p=stream_get_contents(STDIN); echo password_verify($p, $argv[1]) ? "1" : "0";', hash], pw);
    if (php.code === 0) return php.out.trim() === "1";
    const py = await runCmd("python3", ["-c", "import sys,crypt,hmac;p=sys.stdin.read();h=sys.argv[1];print('1' if hmac.compare_digest(crypt.crypt(p,h.replace('$2y$','$2b$',1)) or '',h.replace('$2y$','$2b$',1)) else '0')", hash], pw);
    if (py.code === 0) return py.out.trim() === "1";
  }
  return false;
}

// ---------------------------------------------------------------------
//  Sesi (cookie HttpOnly, idle 12 jam) & batas salah login
// ---------------------------------------------------------------------
const SESSION_IDLE = 12 * 3600;
const COOKIE = "pacs_sess";
const tokHash = (t) => crypto.createHash("sha256").update(String(t)).digest("hex");
function getCookie(req, name) {
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}
const prefixOf = (req) => String(req.headers["x-forwarded-prefix"] || "").replace(/[^\w/.-]/g, "").replace(/\/$/, "") || "";
const cookieFlags = (req) => `HttpOnly; SameSite=Strict; Path=${prefixOf(req) || "/"}${req.headers["x-forwarded-proto"] === "https" ? "; Secure" : ""}`;
function sessionOf(req) {
  const t = getCookie(req, COOKIE);
  if (!t) return null;
  const h = tokHash(t);
  const r = db.prepare("SELECT * FROM sessions WHERE h = ?").get(h);
  if (!r) return null;
  if (now() - r.last > SESSION_IDLE) {
    db.prepare("DELETE FROM sessions WHERE h = ?").run(h);
    return null;
  }
  if (now() - r.last > 60) db.prepare("UPDATE sessions SET last = ? WHERE h = ?").run(now(), h);
  return r;
}
function newSession(req) {
  const t = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions (h, created, last, ip, ua) VALUES (?, ?, ?, ?, ?)").run(tokHash(t), now(), now(), clientIp(req), String(req.headers["user-agent"] || "").slice(0, 200));
  db.prepare("DELETE FROM sessions WHERE last < ?").run(now() - SESSION_IDLE);
  return t;
}
const clientIp = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim().replace(/^::ffff:/, "");
const FAILS = new Map();

// ---------------------------------------------------------------------
//  HTTP keluar (GenieACS NBI & panel utama)
// ---------------------------------------------------------------------
function request(method, url, body, headers, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      return resolve({ status: 0, error: "URL tidak valid" });
    }
    const mod = u.protocol === "https:" ? https : http;
    const raw = typeof body === "string";
    const data = body == null ? null : Buffer.from(raw ? body : JSON.stringify(body));
    const h = Object.assign({ Accept: "application/json" }, headers || {});
    if (data) {
      h["Content-Type"] = raw ? "text/plain" : "application/json";
      h["Content-Length"] = data.length;
    }
    const rq = mod.request(u, { method, headers: h, timeout: timeoutMs || 40000, family: 4 }, (res) => {
      const ch = [];
      res.on("data", (c) => ch.push(c));
      res.on("end", () => {
        const text = Buffer.concat(ch).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          json = null;
        }
        resolve({ status: res.statusCode, json, text });
      });
    });
    rq.on("timeout", () => rq.destroy(new Error("waktu habis")));
    rq.on("error", (e) => resolve({ status: 0, error: e.message }));
    if (data) rq.write(data);
    rq.end();
  });
}
function nbi(S) {
  const base = String(S.acs_url || "").replace(/\/$/, "");
  const auth = S.acs_user ? { Authorization: "Basic " + Buffer.from(`${S.acs_user}:${S.acs_pass || ""}`).toString("base64") } : {};
  const call = async (method, p, body, timeout) => {
    const r = await request(method, base + p, body, auth, timeout);
    r.error = r.status === 0 ? `Tidak bisa terhubung ke GenieACS NBI (${r.error})` : r.status >= 400 ? `GenieACS HTTP ${r.status}: ${String(r.text || "").slice(0, 160)}` : "";
    return r;
  };
  return {
    call,
    async devices(query, projection) {
      const qs = `query=${encodeURIComponent(JSON.stringify(query || {}))}${projection ? `&projection=${encodeURIComponent(projection)}` : ""}`;
      const r = await call("GET", `/devices/?${qs}`, null, 60000);
      return r.status === 200 && Array.isArray(r.json) ? { list: r.json } : { list: [], error: r.error || "Jawaban GenieACS tidak valid" };
    },
    async device(id) {
      const r = await this.devices({ _id: id });
      return r.list[0] || null;
    },
    async task(id, task) {
      const r = await call("POST", `/devices/${encodeURIComponent(id)}/tasks?timeout=5000&connection_request`, task, 20000);
      if (r.status === 200) return { ok: true, msg: "Berhasil dijalankan di perangkat." };
      if (r.status === 202) return { ok: true, queued: true, msg: "Masuk antrian. Dijalankan saat ONT melapor berikutnya." };
      return { ok: false, msg: r.error || `Gagal (HTTP ${r.status})` };
    },
    async tag(id, tag, add) {
      const r = await call(add ? "POST" : "DELETE", `/devices/${encodeURIComponent(id)}/tags/${encodeURIComponent(tag)}`, null, 15000);
      return r.status === 200;
    },
  };
}

// Router & IP virtual dari panel utama (cache 60 detik, data terakhir dipakai bila gagal)
let ROUTERS = { t: 0, v: null };
async function panelRouters(force) {
  const link = panelLink();
  if (!link) return { linked: false, ok: false, routers: [], panel: {}, error: "" };
  if (!force && ROUTERS.v && Date.now() - ROUTERS.t < 60000) return ROUTERS.v;
  const r = await request("GET", link.url.replace(/\/$/, "") + "/api/addon/routers", null, { "X-Addon-Key": link.key }, 8000);
  let out;
  if (r.status === 200 && r.json && Array.isArray(r.json.routers)) {
    out = { linked: true, ok: true, routers: r.json.routers, panel: r.json.panel || {}, error: "" };
    cacheSet("routers", r.json);
  } else {
    const msg = r.status === 0 ? `Panel utama tidak menjawab (${r.error})` : `Panel utama menolak (HTTP ${r.status})`;
    const c = cacheGet("routers", Infinity);
    out = c ? { linked: true, ok: true, stale: true, routers: c.v.routers, panel: c.v.panel || {}, error: msg + " — memakai data terakhir" } : { linked: true, ok: false, routers: [], panel: {}, error: msg };
  }
  ROUTERS = { t: Date.now(), v: out };
  return out;
}
const ip2n = (ip) => {
  const m = String(ip || "").match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null;
};
function routerIndex(routers) {
  const nets = [];
  for (const r of routers) {
    const m = String(r.virtualSubnet || "").match(/^([\d.]+)\/(\d+)$/);
    if (!m) continue;
    const net = ip2n(m[1]);
    nets.push([net, net + 2 ** (32 - +m[2]), r]);
  }
  return (ip) => {
    const n = ip2n(ip);
    if (n === null) return null;
    const x = nets.find(([a, b]) => n >= a && n < b);
    return x ? x[2] : null;
  };
}

// ---------------------------------------------------------------------
//  Pembaca parameter GenieACS (sama dengan versi PHP)
// ---------------------------------------------------------------------
const IGD_WAN = "InternetGatewayDevice.WANDevice.1";
const PARAMS = {
  rx: ["VirtualParameters.RXPower", "VirtualParameters.redaman", "VirtualParameters.rxpower", `${IGD_WAN}.X_FH_GponInterfaceConfig.RXPower`, `${IGD_WAN}.X_GponInterafceConfig.RXPower`, `${IGD_WAN}.X_GponInterfaceConfig.RXPower`, `${IGD_WAN}.X_ZTE-COM_WANPONInterfaceConfig.RXPower`, `${IGD_WAN}.X_CT-COM_GponInterfaceConfig.RXPower`, `${IGD_WAN}.X_CMCC_GponInterfaceConfig.RXPower`, `${IGD_WAN}.X_CU_WANEPONInterfaceConfig.OpticalTransceiver.RXPower`, "Device.Optical.Interface.1.RxPower", "Device.Optical.Interface.1.OpticalSignalLevel"],
  temp: ["VirtualParameters.gettemp", "VirtualParameters.temperature", `${IGD_WAN}.X_FH_GponInterfaceConfig.TransceiverTemperature`, `${IGD_WAN}.X_GponInterafceConfig.TransceiverTemperature`, `${IGD_WAN}.X_ZTE-COM_WANPONInterfaceConfig.Temperature`, `${IGD_WAN}.X_CT-COM_GponInterfaceConfig.TransceiverTemperature`],
  pppoe: ["VirtualParameters.pppoeUsername", "VirtualParameters.pppoeUsername2", `${IGD_WAN}.WANConnectionDevice.*.WANPPPConnection.*.Username`, "Device.PPP.Interface.*.Username"],
  ip: ["VirtualParameters.pppoeIP", `${IGD_WAN}.WANConnectionDevice.*.WANPPPConnection.*.ExternalIPAddress`],
  tr069: ["VirtualParameters.IPTR069", "VirtualParameters.iptr069", "VirtualParameters.ipTR069"],
  mac: ["VirtualParameters.PonMac", "VirtualParameters.ponMac", `${IGD_WAN}.WANConnectionDevice.*.WANIPConnection.*.MACAddress`, "VirtualParameters.pppoeMac", `${IGD_WAN}.WANConnectionDevice.*.WANPPPConnection.*.MACAddress`],
  ssid: ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID", "Device.WiFi.SSID.1.SSID"],
  uptime: ["VirtualParameters.getdeviceuptime", "InternetGatewayDevice.DeviceInfo.UpTime", "Device.DeviceInfo.UpTime"],
  sw: ["InternetGatewayDevice.DeviceInfo.SoftwareVersion", "Device.DeviceInfo.SoftwareVersion"],
  hw: ["InternetGatewayDevice.DeviceInfo.HardwareVersion", "Device.DeviceInfo.HardwareVersion"],
};
const LIST_PROJECTION = ["_id", "_lastInform", "_registered", "_lastBoot", "_lastBootstrap", "_deviceId", "_tags", "VirtualParameters", "InternetGatewayDevice.ManagementServer.ConnectionRequestURL", "Device.ManagementServer.ConnectionRequestURL", "InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "Device.ManagementServer.PeriodicInformInterval", "InternetGatewayDevice.DeviceInfo.UpTime", "InternetGatewayDevice.DeviceInfo.SoftwareVersion", "InternetGatewayDevice.DeviceInfo.HardwareVersion", "InternetGatewayDevice.WANDevice.1", "InternetGatewayDevice.LANDevice.1.WLANConfiguration", "Device.DeviceInfo.UpTime", "Device.DeviceInfo.SoftwareVersion", "Device.DeviceInfo.HardwareVersion", "Device.Optical", "Device.PPP", "Device.IP.Interface", "Device.WiFi.SSID", "Device.WiFi.AccessPoint"].join(",");
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);
const kids = (node) => (isObj(node) ? Object.entries(node).filter(([k, v]) => k && k[0] !== "_" && isObj(v)) : []);
function walk(node, parts, i) {
  if (!isObj(node)) return null;
  if (i === parts.length) return node;
  const p = parts[i];
  if (p === "*") {
    for (const [, child] of kids(node)) {
      const v = walk(child, parts, i + 1);
      if (v !== null && !(isObj(v) && "_value" in v && (v._value === "" || v._value === null))) return v;
    }
    return null;
  }
  return p in node ? walk(node[p], parts, i + 1) : null;
}
const nodeAt = (d, p) => walk(d, p.split("."), 0);
const valAt = (d, p) => {
  const n = nodeAt(d, p);
  return isObj(n) && "_value" in n ? n._value : null;
};
const first = (d, paths) => {
  for (const p of paths) {
    const v = valAt(d, p);
    if (v !== null && v !== "") return v;
  }
  return null;
};
const ts = (v) => (v ? Math.floor(Date.parse(v) / 1000) || 0 : 0);
function rxDbm(v) {
  if (v === null || v === undefined || v === "") return null;
  let n = Number(v);
  if (!Number.isFinite(n)) {
    const m = String(v).match(/-?\d+(\.\d+)?/);
    if (!m) return null;
    n = Number(m[0]);
  }
  if (n <= 0 && n > -60) return Math.round(n * 100) / 100;
  if (n > 0) return Math.round(10 * Math.log10(n / 10000) * 100) / 100;
  return null;
}
const rxClass = (rx, S) => (rx === null ? "na" : rx >= +S.rx_good ? "good" : rx >= +S.rx_fair ? "fair" : "poor");
const off = (v) => v === false || v === 0 || v === "0" || (typeof v === "string" && v.toLowerCase() === "false");
function wlanAssoc(w) {
  let n = null;
  for (const k of ["TotalAssociations", "WLAN_AssociatedDeviceNumberOfEntries", "AssociatedDeviceNumberOfEntries"]) {
    const v = w[k] && w[k]._value;
    if (v !== undefined && v !== "" && Number.isFinite(+v)) {
      n = +v;
      break;
    }
  }
  if (isObj(w.AssociatedDevice)) {
    const c = kids(w.AssociatedDevice).filter(([, a]) => a.AssociatedDeviceMACAddress && a.AssociatedDeviceMACAddress._value).length;
    if (c > 0 && (n === null || c > n)) n = c;
  }
  return n;
}
function wlanClients(d) {
  const vp = first(d, ["VirtualParameters.activedevices", "VirtualParameters.userconnected"]);
  if (vp !== null && Number.isFinite(+vp)) return +vp;
  let total = null;
  for (const [, w] of kids(nodeAt(d, "InternetGatewayDevice.LANDevice.1.WLANConfiguration"))) {
    const n = wlanAssoc(w);
    if (n !== null) total = (total || 0) + n;
  }
  for (const [, a] of kids(nodeAt(d, "Device.WiFi.AccessPoint"))) {
    if (a.AssociatedDeviceNumberOfEntries && a.AssociatedDeviceNumberOfEntries._value !== undefined) total = (total || 0) + (+a.AssociatedDeviceNumberOfEntries._value || 0);
  }
  return total;
}
function wlanBand(idx, w, max) {
  const g = (k) => (w[k] && w[k]._value !== undefined ? String(w[k]._value) : "");
  const f = g("OperatingFrequencyBand").toLowerCase();
  if (f) {
    if (f.includes("2.4") || f.includes("2,4")) return "2.4";
    if (f.includes("5")) return "5";
  }
  const ch = +g("Channel");
  if (ch > 0) return ch > 14 ? "5" : "2.4";
  const st = g("Standard").toLowerCase();
  if (st) {
    if (st.includes("ac") || /(^|[^a-z])a([^a-z]|$)/.test(st)) return "5";
    if (/[bg]/.test(st)) return "2.4";
  }
  if (/(^|[^0-9])5\s?g/i.test(g("SSID"))) return "5";
  if (max > 4 && +idx > max / 2) return "5";
  return "2.4";
}
function ssidBands(d) {
  const out = { "2.4": "", 5: "" };
  for (const base of ["InternetGatewayDevice.LANDevice.1.WLANConfiguration", "Device.WiFi.SSID"]) {
    const list = kids(nodeAt(d, base));
    const max = Math.max(0, ...list.map(([k]) => +k || 0));
    for (const [k, w] of list) {
      const ssid = w.SSID && w.SSID._value ? String(w.SSID._value) : "";
      const en = w.Enable ? w.Enable._value : null;
      if (!ssid || off(en)) continue;
      const b = wlanBand(k, w, max);
      if (!out[b]) out[b] = ssid;
    }
  }
  return out;
}
function macFirst(d, paths) {
  for (const p of paths) {
    const v = valAt(d, p);
    if (v && !/^(0{1,2}[:-]?){5}0{1,2}$/.test(String(v))) return String(v);
  }
  return "";
}
function informInterval(d) {
  const v = +first(d, ["InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "Device.ManagementServer.PeriodicInformInterval"]);
  return v > 0 ? v : 0;
}
function onlineLimit(d, S) {
  const iv = informInterval(d);
  if (S.online_auto !== false && iv > 0) return iv * 2 + 60;
  return (+S.online_minutes || 10) * 60;
}
function tr069Ip(d) {
  const url = first(d, ["InternetGatewayDevice.ManagementServer.ConnectionRequestURL", "Device.ManagementServer.ConnectionRequestURL"]);
  if (url) {
    try {
      return new URL(String(url)).hostname.replace(/^\[|\]$/g, "");
    } catch (e) {
      const m = String(url).match(/\/\/(?:[^@/]*@)?([^:/]+)/);
      if (m) return m[1];
    }
  }
  const v = first(d, PARAMS.tr069);
  return v !== null ? String(v) : "";
}
function detectBrand(vendor, pc, serial, oui) {
  const txt = `${vendor} ${pc}`.toLowerCase();
  const byName = { fiberhome: "FiberHome", "fiber home": "FiberHome", zte: "ZTE", huawei: "Huawei", "c-data": "C-Data", cdata: "C-Data", nokia: "Nokia", alcatel: "Nokia", "tp-link": "TP-Link", tplink: "TP-Link", bdcom: "BDCOM", "v-sol": "V-SOL", vsol: "V-SOL", hsgq: "HSGQ", raisecom: "Raisecom", totolink: "Totolink", tenda: "Tenda", zyxel: "Zyxel", sagemcom: "Sagemcom", optilink: "Optilink", xiaomi: "Xiaomi" };
  for (const [k, b] of Object.entries(byName)) if (txt.includes(k)) return b;
  const bySerial = { FHTT: "FiberHome", ZTEG: "ZTE", ZICG: "ZTE", HWTC: "Huawei", 4857: "Huawei", CDTC: "C-Data", ALCL: "Nokia", TPLG: "TP-Link", VSOL: "V-SOL", HSGQ: "HSGQ" };
  const sp = String(serial || "").slice(0, 4).toUpperCase();
  if (bySerial[sp]) return bySerial[sp];
  const p = String(pc || "").toUpperCase();
  if (/^(HG6|HG2|AN5|SR1)/.test(p)) return "FiberHome";
  if (/^(HG8|EG8|HS8|HN8)/.test(p)) return "Huawei";
  if (/^F[46]\d\d/.test(p)) return "ZTE";
  if (/^FD\d/.test(p)) return "C-Data";
  const byOui = { "000AC2": "FiberHome", "00259E": "Huawei", E0A1D7: "ZTE" };
  if (byOui[String(oui || "").toUpperCase()]) return byOui[String(oui).toUpperCase()];
  const v = String(vendor || "").trim();
  return v && v !== "-" ? v : "Lainnya";
}
function uptimeSecs(v) {
  if (v !== null && v !== "" && Number.isFinite(+v)) return +v;
  const m = String(v || "").match(/(\d+)\s*d\D+(\d+):(\d+):(\d+)/i);
  return m ? +m[1] * 86400 + +m[2] * 3600 + +m[3] * 60 + +m[4] : null;
}
function bootTime(d) {
  let best = 0;
  let bt = 0;
  for (const p of ["InternetGatewayDevice.DeviceInfo.UpTime", "Device.DeviceInfo.UpTime", "VirtualParameters.getdeviceuptime"]) {
    const n = nodeAt(d, p);
    if (!isObj(n) || n._value === undefined) continue;
    const secs = uptimeSecs(n._value);
    const t = ts(n._timestamp);
    if (secs === null || !t) continue;
    if (t > best) {
      best = t;
      bt = t - secs;
    }
  }
  return Math.max(ts(d._lastBoot), bt);
}
function rxPoint(d) {
  for (const p of PARAMS.rx) {
    const n = nodeAt(d, p);
    if (isObj(n) && n._value !== undefined && n._value !== "" && n._value !== null) {
      const rx = rxDbm(n._value);
      if (rx === null) continue;
      return [rx, ts(n._timestamp) || ts(d._lastInform)];
    }
  }
  return [null, 0];
}

// Tag: "nama:Budi_Santoso" = nama pelanggan; tag lain = label bebas.
// Versi lama: tag ke-2 = nama (tag ke-1 = area), atau satu-satunya tag = nama.
const tagText = (t) => String(t || "").replace(/_/g, " ");
const cleanTag = (s) => String(s || "").trim().replace(/\s+/g, "_").replace(/[^A-Za-z0-9_.\-]/g, "").replace(/^_+|_+$/g, "").slice(0, 60);
function tagsSplit(tags) {
  tags = (Array.isArray(tags) ? tags : []).map(String);
  const ni = tags.findIndex((t) => /^nama:/i.test(t));
  if (ni >= 0) return { name: tagText(tags[ni].slice(5)), nameTag: tags[ni], labels: tags.filter((_, i) => i !== ni), legacy: false };
  if (tags.length >= 2) return { name: tagText(tags[1]), nameTag: tags[1], labels: tags.filter((_, i) => i !== 1), legacy: true };
  if (tags.length === 1) return { name: tagText(tags[0]), nameTag: tags[0], labels: [], legacy: true };
  return { name: "", nameTag: "", labels: [], legacy: false };
}

function normalize(d, S, findRouter) {
  const did = d._deviceId || {};
  const last = ts(d._lastInform);
  const rx = rxDbm(first(d, PARAMS.rx));
  const temp = first(d, PARAMS.temp);
  const tags = Array.isArray(d._tags) ? d._tags.map(String) : [];
  const sb = ssidBands(d);
  const tg = tagsSplit(tags);
  const ip = tr069Ip(d);
  const router = ip && findRouter ? findRouter(ip) : null;
  const t = now();
  return {
    id: d._id,
    serial: did._SerialNumber || "-",
    pc: did._ProductClass || "-",
    vendor: did._Manufacturer || "-",
    oui: did._OUI || "-",
    brand: detectBrand(did._Manufacturer || "", did._ProductClass || "", did._SerialNumber || "", did._OUI || ""),
    last,
    registered: ts(d._registered),
    lastBoot: ts(d._lastBoot),
    online: !!last && t - last <= onlineLimit(d, S),
    rx,
    rxc: rxClass(rx, S),
    temp: temp !== null && Number.isFinite(+temp) ? Math.round(+temp * 10) / 10 : temp,
    pppoe: String(first(d, PARAMS.pppoe) || ""),
    ip,
    ipWan: String(first(d, PARAMS.ip) || ""),
    mac: macFirst(d, PARAMS.mac),
    ssid: sb["2.4"] || (sb["5"] ? "" : String(first(d, PARAMS.ssid) || "")),
    ssid5: sb["5"],
    clients: wlanClients(d),
    uptime: uptimeSecs(first(d, PARAMS.uptime)),
    boot: bootTime(d),
    sw: String(first(d, PARAMS.sw) || ""),
    hw: String(first(d, PARAMS.hw) || ""),
    ponMode: String(first(d, ["VirtualParameters.getponmode", "InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.WANAccessType"]) || ""),
    informIv: informInterval(d),
    tags,
    name: tg.name,
    labels: tg.labels,
    legacyTags: tg.legacy,
    routerId: router ? router.id : "",
    router: router ? router.name : "",
    routerOn: router ? !!router.online : null,
    routerTr: router ? router.transport : "",
    tr181: !d.InternetGatewayDevice && !!d.Device,
  };
}

// Detail lengkap satu ONT: WiFi, klien LAN, koneksi WAN
function detail(raw) {
  const wlans = [];
  const wl = nodeAt(raw, "InternetGatewayDevice.LANDevice.1.WLANConfiguration");
  const wlist = kids(wl);
  const wmax = Math.max(0, ...wlist.map(([k]) => +k || 0));
  const g = (o, k) => (o && o[k] && o[k]._value !== undefined ? o[k]._value : null);
  for (const [k, w] of wlist) {
    const as = wlanAssoc(w);
    wlans.push({ idx: k, ssid: g(w, "SSID") || "", enable: g(w, "Enable"), channel: g(w, "Channel"), std: g(w, "Standard"), clients: as, band: wlanBand(k, w, wmax), sec: g(w, "BeaconType"), hidden: w.SSIDAdvertisementEnabled ? off(g(w, "SSIDAdvertisementEnabled")) : null, power: g(w, "TransmitPower") });
  }
  const ws = kids(nodeAt(raw, "Device.WiFi.SSID"));
  for (const [k, w] of ws) wlans.push({ idx: k, ssid: g(w, "SSID") || "", enable: g(w, "Enable"), channel: null, std: null, band: wlanBand(k, w, ws.length), sec: null, hidden: null, power: null, clients: +valAt(raw, `Device.WiFi.AccessPoint.${k}.AssociatedDeviceNumberOfEntries`) || null });
  let hosts = [];
  for (const base of ["InternetGatewayDevice.LANDevice.1.Hosts.Host", "Device.Hosts.Host"]) {
    for (const [, h] of kids(nodeAt(raw, base))) hosts.push({ name: g(h, "HostName") || "", ip: g(h, "IPAddress") || "", mac: g(h, "MACAddress") || g(h, "PhysAddress") || "", iface: g(h, "InterfaceType") || g(h, "Layer2Interface") || "", active: g(h, "Active") });
    if (hosts.length) break;
  }
  // FiberHome: daftar Hosts kosong -> pakai daftar klien WiFi
  if (!hosts.length) {
    for (const [k, w] of wlist) for (const [, a] of kids(w.AssociatedDevice)) if (g(a, "AssociatedDeviceMACAddress")) hosts.push({ name: "", ip: g(a, "AssociatedDeviceIPAddress") || "", mac: g(a, "AssociatedDeviceMACAddress"), iface: `WiFi ${g(w, "SSID") || k}`, active: true });
  }
  hosts = hosts.sort((a, b) => Number(!off(b.active)) - Number(!off(a.active)));
  const wans = [];
  for (const [ci, c] of kids(nodeAt(raw, `${IGD_WAN}.WANConnectionDevice`))) {
    for (const [ot, lbl] of [["WANIPConnection", "IP"], ["WANPPPConnection", "PPPoE"]]) {
      for (const [wi, x] of kids(c[ot])) {
        const name = String(g(x, "Name") || "");
        const type = String(g(x, "ConnectionType") || "");
        let vlan = null;
        for (const vk of ["X_FH_VlanID", "X_FH_VLANID", "X_CT-COM_VLANIDMark", "X_CMCC_VLANIDMark", "X_HW_VLAN", "X_ZTE-COM_VLANID", "VLANID"]) {
          if (g(x, vk) !== null && g(x, vk) !== "") {
            vlan = g(x, vk);
            break;
          }
        }
        if (vlan === null) {
          const m = name.match(/VID_?(\d+)/i);
          if (m) vlan = m[1];
        }
        wans.push({ name: name || `${ot}.${ci}.${wi}`, proto: lbl, mode: /bridg/i.test(type) ? "Bridge" : type ? "Route" : "", type, vlan, ip: g(x, "ExternalIPAddress") || "", user: g(x, "Username") || "", enable: g(x, "Enable"), status: g(x, "ConnectionStatus") || "", uptime: uptimeSecs(g(x, "Uptime")) });
      }
    }
  }
  for (const [k, x] of kids(nodeAt(raw, "Device.PPP.Interface"))) wans.push({ name: g(x, "Name") || `PPP.${k}`, proto: "PPPoE", mode: "Route", type: "", vlan: null, ip: valAt(raw, `Device.PPP.Interface.${k}.IPCP.LocalIPAddress`) || "", user: g(x, "Username") || "", enable: g(x, "Enable"), status: g(x, "ConnectionStatus") || g(x, "Status") || "", uptime: null });
  return { wlans, hosts, wans };
}

// ---------------------------------------------------------------------
//  Daftar ONT (cache 30 detik)
// ---------------------------------------------------------------------
let DEVCACHE = { t: 0, v: null };
async function deviceList(force) {
  if (!force && DEVCACHE.v && Date.now() - DEVCACHE.t < 30000) return DEVCACHE.v;
  const S = loadSettings();
  const [r, pr] = await Promise.all([nbi(S).devices({}, LIST_PROJECTION), panelRouters()]);
  const find = routerIndex(pr.routers || []);
  const v = { error: r.error || "", devices: r.list.map((d) => normalize(d, S, find)), routers: pr.routers || [], panel: { linked: pr.linked, ok: pr.ok, error: pr.error || "", name: (pr.panel && pr.panel.name) || "" }, at: Date.now() };
  if (!r.error || !DEVCACHE.v) DEVCACHE = { t: Date.now(), v };
  return r.error && DEVCACHE.v ? Object.assign({}, DEVCACHE.v, { error: r.error }) : v;
}

// ---------------------------------------------------------------------
//  History redaman (sama dengan versi PHP)
// ---------------------------------------------------------------------
let COLLECTING = false;
async function rxCollect() {
  if (COLLECTING) return { ok: false, error: "Pencatat masih berjalan" };
  COLLECTING = true;
  try {
    const S = loadSettings();
    const r = await nbi(S).devices({}, ["_id", "_lastInform", "VirtualParameters", "InternetGatewayDevice.WANDevice.1", "Device.Optical"].join(","));
    if (r.error && !r.list.length) return { ok: false, error: r.error };
    const last = {};
    for (const x of db.prepare("SELECT dev, MAX(ts) AS ts FROM rx_raw GROUP BY dev").all()) last[x.dev] = x.ts;
    const ins = db.prepare("INSERT OR IGNORE INTO rx_raw (dev, ts, rx, temp) VALUES (?, ?, ?, ?)");
    let n = 0;
    tx(() => {
      for (const d of r.list) {
        const [rx, t] = rxPoint(d);
        if (rx === null || !t) continue;
        if (last[d._id] && t <= last[d._id]) continue; // hanya bila RX benar-benar dibaca ulang
        const tp = first(d, PARAMS.temp);
        ins.run(d._id, t, rx, tp !== null && Number.isFinite(+tp) ? Math.round(+tp * 10) / 10 : null);
        n++;
      }
    });
    rxPrune(S);
    const res = { at: now(), devices: r.list.length, saved: n };
    cacheSet("collect", res);
    return Object.assign({ ok: true }, res);
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    COLLECTING = false;
  }
}
function rxPrune(S) {
  let cut = now() - RX_RAW_DAYS * 86400;
  cut -= cut % 3600;
  const keep = Math.max(14, Math.min(730, +S.rx_keep_days || 90));
  tx(() => {
    db.prepare("INSERT OR REPLACE INTO rx_hour (dev, hour, avg, min, max, n) SELECT dev, (ts / 3600) * 3600 AS hour, AVG(rx), MIN(rx), MAX(rx), COUNT(*) FROM rx_raw WHERE ts < ? GROUP BY dev, hour").run(cut);
    db.prepare("DELETE FROM rx_raw WHERE ts < ?").run(cut);
    db.prepare("DELETE FROM rx_hour WHERE hour < ?").run(now() - keep * 86400);
  });
}
function rxSeries(dev, range) {
  const days = { "1d": 1, "7d": 7, "30d": 30, "90d": 90 }[range] || 7;
  const from = now() - days * 86400;
  let pts = [];
  if (days > RX_RAW_DAYS) {
    for (const r of db.prepare("SELECT hour AS ts, avg AS rx, min, max FROM rx_hour WHERE dev = ? AND hour >= ? ORDER BY hour").all(dev, from)) pts.push({ t: r.ts, rx: Math.round(r.rx * 100) / 100, min: r.min, max: r.max });
  }
  const raw = db.prepare("SELECT ts, rx FROM rx_raw WHERE dev = ? AND ts >= ? ORDER BY ts").all(dev, from);
  if (days > RX_RAW_DAYS) {
    const b = new Map();
    for (const r of raw) {
      const h = r.ts - (r.ts % 3600);
      if (!b.has(h)) b.set(h, []);
      b.get(h).push(r.rx);
    }
    for (const [h, v] of b) pts.push({ t: h, rx: Math.round((v.reduce((a, x) => a + x, 0) / v.length) * 100) / 100, min: Math.min(...v), max: Math.max(...v) });
  } else pts = raw.map((r) => ({ t: r.ts, rx: r.rx }));
  const vals = pts.map((p) => p.rx);
  return {
    points: pts,
    stats: vals.length ? { min: Math.min(...pts.map((p) => (p.min !== undefined ? p.min : p.rx))), max: Math.max(...pts.map((p) => (p.max !== undefined ? p.max : p.rx))), avg: Math.round((vals.reduce((a, x) => a + x, 0) / vals.length) * 100) / 100, n: vals.length } : null,
  };
}
// Perubahan RX 24 jam: nilai terbaru dikurangi rata-rata 22–26 jam lalu (negatif = memburuk)
function rxDelta24() {
  const t = now();
  const old = {};
  for (const r of db.prepare("SELECT dev, AVG(rx) AS rx FROM rx_raw WHERE ts BETWEEN ? AND ? GROUP BY dev").all(t - 26 * 3600, t - 22 * 3600)) old[r.dev] = r.rx;
  const out = {};
  if (!Object.keys(old).length) return out;
  for (const r of db.prepare("SELECT r.dev, r.rx FROM rx_raw r JOIN (SELECT dev, MAX(ts) AS ts FROM rx_raw WHERE ts >= ? GROUP BY dev) m ON m.dev = r.dev AND m.ts = r.ts").all(t - 6 * 3600)) {
    if (old[r.dev] !== undefined) out[r.dev] = Math.round((r.rx - old[r.dev]) * 100) / 100;
  }
  return out;
}
function rxStatus() {
  const c = cacheGet("collect", Infinity);
  const one = (q) => (db.prepare(q).get() || {}).n || 0;
  let size = 0;
  try {
    size = fs.statSync(DB_FILE).size;
  } catch (e) {
    // belum ada
  }
  return { last: c ? c.v : null, points: one("SELECT COUNT(*) AS n FROM rx_raw") + one("SELECT COUNT(*) AS n FROM rx_hour"), devs: one("SELECT COUNT(DISTINCT dev) AS n FROM rx_raw"), since: one("SELECT MIN(t) AS n FROM (SELECT MIN(ts) AS t FROM rx_raw UNION SELECT MIN(hour) FROM rx_hour)"), size };
}
function rxProvisionScript() {
  const paths = PARAMS.rx.filter((p) => !p.startsWith("VirtualParameters.")).concat(PARAMS.rx.filter((p) => p.startsWith("VirtualParameters.")));
  return [
    "// Dibuat oleh Panel ACS: baca ulang redaman (RX) setiap Inform untuk history grafik.",
    "// Aman dihapus dari Panel ACS → Pengaturan → History redaman.",
    `const paths = ${JSON.stringify(paths)};`,
    "const fresh = Date.now() - 4 * 60 * 1000;",
    "for (const p of paths) {",
    "  const cur = declare(p, {value: 1});",
    "  if (cur.size) {",
    "    declare(p, {value: fresh});",
    "    break;",
    "  }",
    "}",
    "",
  ].join("\n");
}
async function provisionState(S) {
  const r = await nbi(S).call("GET", `/presets/?query=${encodeURIComponent(JSON.stringify({ _id: RX_PROVISION }))}`, null, 10000);
  return r.status === 200 && Array.isArray(r.json) ? r.json.length > 0 : null;
}

// ---------------------------------------------------------------------
//  HTTP
// ---------------------------------------------------------------------
function send(res, code, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(body) }, headers || {}));
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const ch = [];
    req.on("data", (c) => {
      n += c.length;
      if (n > 1e6) {
        reject(new Error("terlalu besar"));
        req.destroy();
      } else ch.push(c);
    });
    req.on("end", () => {
      try {
        resolve(ch.length ? JSON.parse(Buffer.concat(ch).toString("utf8")) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}
const STATIC = { "/": ["public/index.html", "text/html; charset=utf-8"], "/index.html": ["public/index.html", "text/html; charset=utf-8"], "/assets/chart.umd.js": ["assets/chart.umd.js", "application/javascript; charset=utf-8"] };
const SEC_HEADERS = { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "same-origin" };
function serveStatic(req, res, p) {
  const f = STATIC[p];
  if (!f) return false;
  const file = path.join(APP_DIR, f[0]);
  fs.readFile(file, (err, buf) => {
    if (err) {
      res.writeHead(404);
      return res.end("Tidak ditemukan");
    }
    res.writeHead(200, Object.assign({ "Content-Type": f[1], "Cache-Control": p.startsWith("/assets/") ? "public, max-age=86400" : "no-cache" }, SEC_HEADERS));
    res.end(buf);
  });
  return true;
}

async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const method = req.method;
  if (method === "GET" && serveStatic(req, res, p)) return;
  if (!p.startsWith("/api/")) {
    res.writeHead(404, SEC_HEADERS);
    return res.end("Tidak ditemukan");
  }
  // Perlindungan CSRF: permintaan yang mengubah data wajib header X-Req (tidak bisa dikirim form lintas situs)
  if (method !== "GET" && req.headers["x-req"] !== "1") return send(res, 403, { error: "Permintaan ditolak." });
  let body = {};
  if (method !== "GET") {
    try {
      body = await readBody(req);
    } catch (e) {
      return send(res, 400, { error: "Data tidak valid." });
    }
  }
  const S = loadSettings();

  // --- Login ---
  if (p === "/api/me") {
    const s = sessionOf(req);
    return send(res, 200, { loggedIn: !!s, setup: !S.admin_pass, appName: S.app_name || "Panel ACS", user: s ? S.admin_user : "", version: VERSION });
  }
  if (p === "/api/setup" && method === "POST") {
    if (S.admin_pass) return send(res, 400, { error: "Akun admin sudah dibuat." });
    const u = String(body.user || "").trim();
    if (!/^[\w.-]{3,32}$/.test(u)) return send(res, 400, { error: "Username 3–32 karakter (huruf, angka, titik, minus, garis bawah)." });
    if (String(body.pass || "").length < 8) return send(res, 400, { error: "Password minimal 8 karakter." });
    saveSettings({ admin_user: u, admin_pass: hashPw(body.pass) });
    return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=${newSession(req)}; ${cookieFlags(req)}` });
  }
  if (p === "/api/login" && method === "POST") {
    const ip = clientIp(req);
    const f = FAILS.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return send(res, 429, { error: `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((f.until - Date.now()) / 60000)} menit.` });
    const okUser = String(body.user || "").trim() === String(S.admin_user);
    const ok = okUser && (await verifyPw(String(body.pass || ""), S.admin_pass));
    if (!ok) {
      f.n++;
      if (f.n >= 5) {
        f.until = Date.now() + 5 * 60000;
        f.n = 0;
      }
      FAILS.set(ip, f);
      await new Promise((r) => setTimeout(r, 700));
      return send(res, 401, { error: "Username atau password salah." });
    }
    FAILS.delete(ip);
    if (!String(S.admin_pass).startsWith("scrypt$")) saveSettings({ admin_pass: hashPw(body.pass) }); // ganti hash lama
    return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=${newSession(req)}; ${cookieFlags(req)}` });
  }
  if (p === "/api/logout" && method === "POST") {
    const t = getCookie(req, COOKIE);
    if (t) db.prepare("DELETE FROM sessions WHERE h = ?").run(tokHash(t));
    return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=; ${cookieFlags(req)}; Max-Age=0` });
  }
  if (!sessionOf(req)) return send(res, 401, { error: "Silakan login." });

  // --- Status koneksi (header) ---
  if (p === "/api/status") {
    const [pr, t] = await Promise.all([panelRouters(url.searchParams.get("refresh") === "1"), nbi(S).call("GET", "/devices/?projection=_id&limit=1", null, 8000)]);
    return send(res, 200, { nbi: { ok: t.status === 200, error: t.error || "" }, panel: { linked: pr.linked, ok: pr.ok, error: pr.error || "", routers: (pr.routers || []).length, name: (pr.panel && pr.panel.name) || "" }, collect: rxStatus().last });
  }
  // --- Daftar ONT & ringkasan ---
  if (p === "/api/devices") {
    const v = await deviceList(url.searchParams.get("refresh") === "1");
    const delta = rxDelta24();
    const faults = await nbi(S).call("GET", "/faults/?projection=_id,device", null, 10000);
    return send(res, 200, Object.assign({}, v, { delta, faults: Array.isArray(faults.json) ? faults.json.length : 0, faultDevs: Array.isArray(faults.json) ? [...new Set(faults.json.map((x) => x.device))] : [], thresholds: { good: +S.rx_good, fair: +S.rx_fair, drop: +S.rx_drop_db } }));
  }
  if (p === "/api/device") {
    const id = url.searchParams.get("id") || "";
    const raw = await nbi(S).device(id);
    if (!raw) return send(res, 404, { error: "ONT tidak ditemukan di GenieACS." });
    const pr = await panelRouters();
    const d = normalize(raw, S, routerIndex(pr.routers || []));
    const router = d.routerId ? (pr.routers || []).find((r) => r.id === d.routerId) : null;
    return send(res, 200, Object.assign(d, detail(raw), { routerInfo: router ? { name: router.name, virtualSubnet: router.virtualSubnet, transport: router.transport, online: !!router.online } : null, panelLinked: pr.linked, delta: rxDelta24()[id] ?? null }));
  }
  if (p === "/api/device/action" && method === "POST") {
    const id = String(body.id || "");
    const act = body.action;
    let r;
    if (act === "reboot") r = await nbi(S).task(id, { name: "reboot" });
    else if (act === "refresh") r = await nbi(S).task(id, { name: "refreshObject", objectName: body.tr181 ? "Device" : "InternetGatewayDevice" });
    else return send(res, 400, { error: "Aksi tidak dikenal." });
    DEVCACHE.t = 0;
    return send(res, r.ok ? 200 : 400, r.ok ? r : { error: r.msg });
  }
  if (p === "/api/device/wifi" && method === "POST") {
    const id = String(body.id || "");
    const raw = await nbi(S).device(id);
    if (!raw) return send(res, 404, { error: "ONT tidak ditemukan." });
    const idx = Math.max(1, parseInt(body.index, 10) || 1);
    const ssid = String(body.ssid || "").trim();
    const pass = String(body.pass || "");
    if (pass && (pass.length < 8 || pass.length > 63)) return send(res, 400, { error: "Password WiFi 8–63 karakter." });
    if (ssid.length > 32) return send(res, 400, { error: "SSID maksimal 32 karakter." });
    const pv = [];
    if (raw.InternetGatewayDevice) {
      const b = `InternetGatewayDevice.LANDevice.1.WLANConfiguration.${idx}`;
      if (ssid) pv.push([`${b}.SSID`, ssid, "xsd:string"]);
      if (pass) pv.push([nodeAt(raw, `${b}.PreSharedKey.1.KeyPassphrase`) ? `${b}.PreSharedKey.1.KeyPassphrase` : nodeAt(raw, `${b}.KeyPassphrase`) ? `${b}.KeyPassphrase` : `${b}.PreSharedKey.1.PreSharedKey`, pass, "xsd:string"]);
    } else {
      if (ssid) pv.push([`Device.WiFi.SSID.${idx}.SSID`, ssid, "xsd:string"]);
      if (pass) pv.push([`Device.WiFi.AccessPoint.${idx}.Security.KeyPassphrase`, pass, "xsd:string"]);
    }
    if (!pv.length) return send(res, 400, { error: "Isi SSID atau password." });
    const r = await nbi(S).task(id, { name: "setParameterValues", parameterValues: pv });
    DEVCACHE.t = 0;
    return send(res, r.ok ? 200 : 400, r.ok ? r : { error: r.msg });
  }
  // Nama pelanggan + label (tag GenieACS)
  if (p === "/api/device/tags" && method === "POST") {
    const id = String(body.id || "");
    const raw = await nbi(S).devices({ _id: id }, "_id,_tags");
    const dev = raw.list[0];
    if (!dev) return send(res, 404, { error: "ONT tidak ditemukan." });
    const cur = (dev._tags || []).map(String);
    const tg = tagsSplit(cur);
    const name = cleanTag(body.name);
    const labels = [...new Set((Array.isArray(body.labels) ? body.labels : []).map(cleanTag).filter((t) => t && !/^nama:/i.test(t)))];
    const want = (name ? [`nama:${name}`] : []).concat(labels);
    // tag nama lama (konvensi lama) diganti tag "nama:"
    const drop = cur.filter((t) => !want.includes(t) && (t === tg.nameTag || /^nama:/i.test(t) || !labels.includes(t)));
    const add = want.filter((t) => !cur.includes(t));
    let ok = true;
    const N = nbi(S);
    for (const t of drop) ok = (await N.tag(id, t, false)) && ok;
    for (const t of add) ok = (await N.tag(id, t, true)) && ok;
    DEVCACHE.t = 0;
    return ok ? send(res, 200, { ok: true, tags: want }) : send(res, 400, { error: "Sebagian tag gagal disimpan di GenieACS." });
  }
  if (p === "/api/rx") return send(res, 200, rxSeries(url.searchParams.get("id") || "", url.searchParams.get("range") || "7d"));
  // --- Faults ---
  if (p === "/api/faults" && method === "GET") {
    const r = await nbi(S).call("GET", "/faults/", null, 20000);
    if (r.status !== 200) return send(res, 400, { error: r.error });
    const v = await deviceList();
    const byId = new Map(v.devices.map((d) => [d.id, d]));
    return send(res, 200, { faults: (r.json || []).map((f) => ({ id: f._id, device: f.device, channel: f.channel, code: f.code, message: f.message, detail: f.detail ? (typeof f.detail === "string" ? f.detail : JSON.stringify(f.detail)).slice(0, 500) : "", retries: f.retries, timestamp: ts(f.timestamp), name: (byId.get(f.device) || {}).name || "", serial: (byId.get(f.device) || {}).serial || "" })) });
  }
  if (p === "/api/faults" && method === "DELETE") {
    const N = nbi(S);
    let ids = body.all ? ((await N.call("GET", "/faults/?projection=_id", null, 20000)).json || []).map((f) => f._id) : [String(body.id || "")];
    let n = 0;
    for (const id of ids) if ((await N.call("DELETE", `/faults/${encodeURIComponent(id)}`, null, 10000)).status === 200) n++;
    return send(res, 200, { ok: true, count: n });
  }
  // --- Pengaturan ---
  if (p === "/api/settings" && method === "GET") {
    const prov = await provisionState(S);
    const link = panelLink();
    return send(res, 200, { app_name: S.app_name, acs_url: S.acs_url, acs_user: S.acs_user, acs_pass_set: !!S.acs_pass, online_auto: S.online_auto !== false, online_minutes: +S.online_minutes, rx_good: +S.rx_good, rx_fair: +S.rx_fair, rx_keep_days: +S.rx_keep_days, rx_drop_db: +S.rx_drop_db, admin_user: S.admin_user, provision: prov, rx: rxStatus(), link: link ? { url: link.url, prefix: link.prefix || "", nbi: link.nbi || "" } : null, version: VERSION });
  }
  if (p === "/api/settings" && method === "PUT") {
    const patch = {};
    if (body.app_name !== undefined) patch.app_name = String(body.app_name).trim().slice(0, 40) || "Panel ACS";
    if (body.acs_url !== undefined) {
      const u = String(body.acs_url).trim().replace(/\/$/, "");
      if (!/^https?:\/\/[^\s]+$/.test(u)) return send(res, 400, { error: "URL NBI tidak valid, contoh http://127.0.0.1:7557" });
      patch.acs_url = u;
    }
    if (body.acs_user !== undefined) patch.acs_user = String(body.acs_user).trim();
    if (body.acs_pass_clear) patch.acs_pass = "";
    else if (body.acs_pass) patch.acs_pass = String(body.acs_pass);
    if (body.online_auto !== undefined) patch.online_auto = !!body.online_auto;
    if (body.online_minutes !== undefined) patch.online_minutes = Math.max(1, Math.min(1440, parseInt(body.online_minutes, 10) || 10));
    if (body.rx_good !== undefined || body.rx_fair !== undefined) {
      const g = +body.rx_good;
      const f = +body.rx_fair;
      if (!(g < 0 && f < 0 && g > f)) return send(res, 400, { error: "Batas RX: Baik harus lebih besar dari Cukup, keduanya negatif (contoh -23 dan -27)." });
      patch.rx_good = g;
      patch.rx_fair = f;
    }
    if (body.rx_keep_days !== undefined) patch.rx_keep_days = Math.max(14, Math.min(730, parseInt(body.rx_keep_days, 10) || 90));
    if (body.rx_drop_db !== undefined) patch.rx_drop_db = Math.max(0.5, Math.min(20, +body.rx_drop_db || 2));
    saveSettings(patch);
    DEVCACHE.t = 0;
    return send(res, 200, { ok: true });
  }
  if (p === "/api/settings/test" && method === "POST") {
    const T = Object.assign({}, S);
    if (body.acs_url) T.acs_url = String(body.acs_url).trim().replace(/\/$/, "");
    if (body.acs_user !== undefined) T.acs_user = String(body.acs_user).trim();
    if (body.acs_pass) T.acs_pass = String(body.acs_pass);
    const r = await nbi(T).call("GET", "/devices/?projection=_id", null, 15000);
    return r.status === 200 && Array.isArray(r.json) ? send(res, 200, { ok: true, msg: `Terhubung ke GenieACS NBI — ${r.json.length} ONT terbaca.` }) : send(res, 400, { error: r.error || `HTTP ${r.status}` });
  }
  if (p === "/api/rx/provision" && method === "POST") {
    const N = nbi(S);
    if (body.remove) {
      await N.call("DELETE", `/presets/${RX_PROVISION}`, null, 10000);
      await N.call("DELETE", `/provisions/${RX_PROVISION}`, null, 10000);
      return send(res, 200, { ok: true, msg: "Provision RX dihapus." });
    }
    const a = await N.call("PUT", `/provisions/${RX_PROVISION}`, rxProvisionScript(), 10000);
    if (a.status !== 200) return send(res, 400, { error: "Gagal membuat provision: " + a.error });
    const preset = { weight: 100, channel: "panel-acs", events: { "2 PERIODIC": true }, precondition: "", configurations: [{ type: "provision", name: RX_PROVISION, args: null }] };
    const b = await N.call("PUT", `/presets/${RX_PROVISION}`, preset, 10000);
    if (b.status !== 200) {
      await N.call("DELETE", `/provisions/${RX_PROVISION}`, null, 10000);
      return send(res, 400, { error: "Gagal membuat preset: " + b.error });
    }
    return send(res, 200, { ok: true, msg: "Provision RX dipasang. RX dibaca ulang setiap inform berkala." });
  }
  if (p === "/api/rx/collect" && method === "POST") {
    const r = await rxCollect();
    return r.ok ? send(res, 200, { ok: true, msg: `${r.devices} ONT dibaca, ${r.saved} titik redaman baru disimpan.` }) : send(res, 400, { error: r.error });
  }
  if (p === "/api/account" && method === "PUT") {
    if (!(await verifyPw(String(body.old || ""), S.admin_pass))) return send(res, 400, { error: "Password lama salah." });
    const patch = {};
    const u = String(body.user || "").trim();
    if (u && u !== S.admin_user) {
      if (!/^[\w.-]{3,32}$/.test(u)) return send(res, 400, { error: "Username 3–32 karakter." });
      patch.admin_user = u;
    }
    if (body.pass) {
      if (String(body.pass).length < 8) return send(res, 400, { error: "Password baru minimal 8 karakter." });
      patch.admin_pass = hashPw(body.pass);
    }
    saveSettings(patch);
    if (patch.admin_pass) {
      const cur = tokHash(getCookie(req, COOKIE));
      db.prepare("DELETE FROM sessions WHERE h != ?").run(cur);
    }
    return send(res, 200, { ok: true });
  }
  return send(res, 404, { error: "Tidak ditemukan." });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "Kesalahan server: " + e.message });
  });
});
server.listen(PORT, HOST, () => console.log(`Panel ACS ${VERSION} berjalan di http://${HOST}:${PORT}`));
// Pencatat redaman berkala (pengganti timer systemd versi PHP)
setTimeout(() => rxCollect().then((r) => r.ok && console.log(`Redaman: ${r.devices} ONT dibaca, ${r.saved} titik baru`)), 60 * 1000);
setInterval(() => rxCollect().then((r) => (r.ok ? console.log(`Redaman: ${r.devices} ONT dibaca, ${r.saved} titik baru`) : console.error("Pencatat redaman:", r.error))), COLLECT_MS);
