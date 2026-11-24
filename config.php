<?php
/**
 * config.php — pengaturan dasar, database SQLite, dan penghubung ke panel utama
 * Panel ACS (monitoring ONT GenieACS)
 */
define('DATA_DIR', __DIR__ . '/data');
define('DB_FILE', DATA_DIR . '/panel-acs.db');
define('PANEL_LINK_FILE', DATA_DIR . '/panel-link.json');
define('APP_VERSION', '2.0.0');

/* ---------- Sesi ---------- */
function req_https()
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    return isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';
}
/** Awalan alamat saat dibuka lewat panel utama (mis. "/acs"), kosong bila dipasang sendiri. */
function base_prefix()
{
    $p = isset($_SERVER['HTTP_X_FORWARDED_PREFIX']) ? (string) $_SERVER['HTTP_X_FORWARDED_PREFIX'] : '';
    return preg_match('#^/[a-z0-9-]+$#', $p) ? $p : '';
}
if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_NONE) {
    session_name('ACSPANEL');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => (base_prefix() ?: '') . '/',
        'secure'   => req_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

/* ---------- Database ---------- */
function ensure_data_dir()
{
    if (!is_dir(DATA_DIR)) {
        @mkdir(DATA_DIR, 0750, true);
    }
    // Perlindungan bila dipasang di hosting Apache
    $ht = DATA_DIR . '/.htaccess';
    if (!file_exists($ht)) {
        @file_put_contents($ht, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    if (!file_exists(DATA_DIR . '/index.html')) {
        @file_put_contents(DATA_DIR . '/index.html', '');
    }
}

/** Koneksi SQLite (dibuat sekali per permintaan). */
function db()
{
    static $pdo = null;
    if ($pdo) {
        return $pdo;
    }
    ensure_data_dir();
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;');
    db_migrate($pdo);
    return $pdo;
}

/** Skema database. Versi dinaikkan setiap ada perubahan tabel. */
function db_migrate($pdo)
{
    $v = (int) $pdo->query('PRAGMA user_version')->fetchColumn();
    if ($v < 1) {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS locations (dev TEXT PRIMARY KEY, lat REAL NOT NULL, lng REAL NOT NULL, updated INTEGER);
            CREATE TABLE IF NOT EXISTS rx_raw (dev TEXT NOT NULL, ts INTEGER NOT NULL, rx REAL, temp REAL, PRIMARY KEY (dev, ts)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS rx_hour (dev TEXT NOT NULL, hour INTEGER NOT NULL, avg REAL, min REAL, max REAL, n INTEGER, PRIMARY KEY (dev, hour)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS rx_raw_ts ON rx_raw (ts);
            CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, ts INTEGER);
            PRAGMA user_version = 1;
        ");
        import_json_data($pdo);
    }
}

/** Data lama (versi JSON): settings.json dan locations.json diimpor sekali, berkas lama disimpan sebagai cadangan. */
function import_json_data($pdo)
{
    $old = DATA_DIR . '/settings.json';
    if (file_exists($old)) {
        $s = json_decode((string) @file_get_contents($old), true);
        if (is_array($s)) {
            $st = $pdo->prepare('INSERT OR REPLACE INTO settings (k, v) VALUES (?, ?)');
            foreach ($s as $k => $v) {
                $st->execute([$k, json_encode($v)]);
            }
        }
        @rename($old, $old . '.bak');
    }
    $old = DATA_DIR . '/locations.json';
    if (file_exists($old)) {
        $l = json_decode((string) @file_get_contents($old), true);
        if (is_array($l)) {
            $st = $pdo->prepare('INSERT OR REPLACE INTO locations (dev, lat, lng, updated) VALUES (?, ?, ?, ?)');
            foreach ($l as $dev => $p) {
                if (isset($p['lat'], $p['lng'])) {
                    $st->execute([$dev, (float) $p['lat'], (float) $p['lng'], time()]);
                }
            }
        }
        @rename($old, $old . '.bak');
    }
    // Profil/grup lama tidak dipakai lagi: router diambil dari panel utama
    if (file_exists(DATA_DIR . '/groups.json')) {
        @rename(DATA_DIR . '/groups.json', DATA_DIR . '/groups.json.bak');
    }
}

/* ---------- Pengaturan ---------- */
function default_settings()
{
    return [
        'app_name'       => 'Panel ACS',
        'acs_url'        => 'http://127.0.0.1:7557', // alamat NBI GenieACS (bukan UI port 3000)
        'acs_user'       => '',                      // isi jika NBI pakai basic auth
        'acs_pass'       => '',
        'online_minutes' => 10,                      // dianggap offline jika tidak inform > X menit
        'online_auto'    => true,
        'rx_good'        => -23,                     // RX >= nilai ini = Excellent
        'rx_fair'        => -27,                     // RX >= nilai ini = Fair, di bawahnya = Poor
        'rx_keep_days'   => 90,                      // lama history redaman disimpan
        'rx_drop_db'     => 2,                       // tanda "memburuk" bila turun >= X dB dalam 24 jam
        'timezone'       => 'Asia/Makassar',
        'admin_user'     => 'admin',
        'admin_pass'     => '',                      // kosong = halaman pertama meminta membuat akun admin
    ];
}

function load_settings()
{
    $s = default_settings();
    foreach (db()->query('SELECT k, v FROM settings') as $r) {
        $s[$r['k']] = json_decode($r['v'], true);
    }
    return $s;
}

function save_settings($s)
{
    try {
        $pdo = db();
        $pdo->beginTransaction();
        $st = $pdo->prepare('INSERT OR REPLACE INTO settings (k, v) VALUES (?, ?)');
        foreach ($s as $k => $v) {
            $st->execute([$k, json_encode($v)]);
        }
        $pdo->commit();
        return true;
    } catch (Exception $e) {
        return false;
    }
}

/* ---------- Lokasi ONT (peta) ---------- */
function locations_all()
{
    $out = [];
    foreach (db()->query('SELECT dev, lat, lng FROM locations') as $r) {
        $out[$r['dev']] = ['lat' => (float) $r['lat'], 'lng' => (float) $r['lng']];
    }
    return $out;
}
function location_set($dev, $lat, $lng)
{
    $st = db()->prepare('INSERT OR REPLACE INTO locations (dev, lat, lng, updated) VALUES (?, ?, ?, ?)');
    return $st->execute([$dev, $lat, $lng, time()]);
}
function location_del($dev)
{
    return db()->prepare('DELETE FROM locations WHERE dev = ?')->execute([$dev]);
}

/* ---------- Cache kecil ---------- */
function cache_get($k, $maxAge)
{
    $st = db()->prepare('SELECT v, ts FROM cache WHERE k = ?');
    $st->execute([$k]);
    $r = $st->fetch();
    if (!$r) {
        return null;
    }
    return ['v' => json_decode($r['v'], true), 'fresh' => (time() - (int) $r['ts']) <= $maxAge, 'ts' => (int) $r['ts']];
}
function cache_set($k, $v)
{
    db()->prepare('INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)')->execute([$k, json_encode($v), time()]);
}

/* ---------- Panel utama (router & IP virtual) ---------- */
function panel_link()
{
    static $l = false;
    if ($l === false) {
        $l = file_exists(PANEL_LINK_FILE) ? json_decode((string) @file_get_contents(PANEL_LINK_FILE), true) : null;
        if (!is_array($l) || empty($l['url']) || empty($l['key'])) {
            $l = null;
        }
    }
    return $l;
}

/**
 * Daftar router dari panel utama (cache 60 detik). Mengembalikan
 * ['ok'=>bool, 'routers'=>[...], 'panel'=>[...], 'error'=>string, 'linked'=>bool].
 */
function panel_routers()
{
    static $res = null;
    if ($res !== null) {
        return $res;
    }
    $link = panel_link();
    if (!$link) {
        return $res = ['ok' => false, 'linked' => false, 'routers' => [], 'panel' => [], 'error' => ''];
    }
    $c = cache_get('routers', 60);
    if ($c && $c['fresh']) {
        return $res = ['ok' => true, 'linked' => true, 'routers' => $c['v']['routers'], 'panel' => $c['v']['panel'], 'error' => ''];
    }
    $ch = curl_init(rtrim($link['url'], '/') . '/api/addon/routers');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_HTTPHEADER     => ['X-Addon-Key: ' . $link['key'], 'Accept: application/json'],
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $j = $body !== false ? json_decode($body, true) : null;
    if ($code === 200 && is_array($j) && isset($j['routers'])) {
        cache_set('routers', $j);
        return $res = ['ok' => true, 'linked' => true, 'routers' => $j['routers'], 'panel' => $j['panel'], 'error' => ''];
    }
    $msg = $body === false ? 'Panel utama tidak menjawab: ' . $err : 'Panel utama menolak (HTTP ' . $code . ')';
    if ($c) {
        return $res = ['ok' => true, 'linked' => true, 'routers' => $c['v']['routers'], 'panel' => $c['v']['panel'], 'error' => $msg . ' — memakai data terakhir'];
    }
    return $res = ['ok' => false, 'linked' => true, 'routers' => [], 'panel' => [], 'error' => $msg];
}

function ip2long_safe($ip)
{
    $n = ip2long((string) $ip);
    return $n === false ? null : sprintf('%u', $n) + 0;
}
/** Router panel utama yang IP virtualnya memuat IP ini, atau null. */
function router_for_ip($ip)
{
    static $nets = null;
    if ($nets === null) {
        $nets = [];
        foreach (panel_routers()['routers'] as $r) {
            if (!preg_match('#^(\d+\.\d+\.\d+\.\d+)/(\d+)$#', (string) $r['virtualSubnet'], $m)) {
                continue;
            }
            $net = ip2long_safe($m[1]);
            $size = 2 ** (32 - (int) $m[2]);
            $nets[] = [$net, $net + $size, $r];
        }
    }
    $n = ip2long_safe($ip);
    if ($n === null) {
        return null;
    }
    foreach ($nets as $x) {
        if ($n >= $x[0] && $n < $x[1]) {
            return $x[2];
        }
    }
    return null;
}

/* ---------- Lain-lain ---------- */
function csrf_token()
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}
