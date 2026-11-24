<?php
/**
 * index.php — Panel Monitoring GenieACS
 * Halaman: dashboard, devices, device, faults, mapping, settings
 * Router ONT diambil dari panel utama (IP virtual), history redaman dari database.
 */
require __DIR__ . '/config.php';
require __DIR__ . '/genieacs.php';
require __DIR__ . '/history.php';

$S = load_settings();
@date_default_timezone_set($S['timezone'] ?: 'Asia/Makassar');
$page = isset($_GET['page']) ? preg_replace('/[^a-z_]/', '', $_GET['page']) : 'dashboard';

/* ======================= LOGOUT ======================= */
if ($page === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: ./');
    exit;
}

/* ======================= LOGIN ======================= */
if (empty($_SESSION['auth'])) {
    if (isset($_GET['action'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'msg' => 'Sesi habis, silakan login ulang.']);
        exit;
    }
    $err = '';
    // Pertama kali dipasang: buat akun admin dulu (tidak ada password bawaan)
    if (empty($S['admin_pass'])) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setup'])) {
            $u = trim(isset($_POST['username']) ? $_POST['username'] : '');
            $p = isset($_POST['password']) ? (string) $_POST['password'] : '';
            $p2 = isset($_POST['password2']) ? (string) $_POST['password2'] : '';
            if (!preg_match('/^[A-Za-z0-9_.-]{3,32}$/', $u)) {
                $err = 'Username 3-32 karakter (huruf, angka, titik, minus, garis bawah).';
            } elseif (strlen($p) < 8) {
                $err = 'Password minimal 8 karakter.';
            } elseif ($p !== $p2) {
                $err = 'Ulangi password tidak sama.';
            } else {
                $S['admin_user'] = $u;
                $S['admin_pass'] = password_hash($p, PASSWORD_DEFAULT);
                save_settings($S);
                session_regenerate_id(true);
                $_SESSION['auth'] = true;
                header('Location: ./');
                exit;
            }
        }
        render_login($S, $err, true);
        exit;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $u = trim(isset($_POST['username']) ? $_POST['username'] : '');
        $p = isset($_POST['password']) ? $_POST['password'] : '';
        if (hash_equals((string) $S['admin_user'], $u) && password_verify($p, $S['admin_pass'])) {
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            header('Location: ./');
            exit;
        }
        sleep(1);
        $err = 'Username atau password salah.';
    }
    render_login($S, $err);
    exit;
}

/* ======================= AJAX ACTIONS ======================= */
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    $in = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($in)) {
        $in = [];
    }
    $hdr = isset($_SERVER['HTTP_X_CSRF']) ? $_SERVER['HTTP_X_CSRF'] : '';
    if (!hash_equals(csrf_token(), $hdr)) {
        echo json_encode(['ok' => false, 'msg' => 'Token tidak valid, muat ulang halaman.']);
        exit;
    }
    $acs = new GenieACS($S);
    $id  = isset($in['id']) ? (string) $in['id'] : '';
    $r   = ['ok' => false, 'msg' => 'Aksi tidak dikenal'];

    switch ($_GET['action']) {
        case 'refresh':
            $root = (isset($in['tr181']) && $in['tr181']) ? 'Device' : 'InternetGatewayDevice';
            $r = $acs->task($id, ['name' => 'refreshObject', 'objectName' => $root]);
            break;

        case 'reboot':
            $r = $acs->task($id, ['name' => 'reboot']);
            break;

        case 'wifi':
            $dev = $acs->device($id);
            if (!$dev) {
                $r = ['ok' => false, 'msg' => 'Perangkat tidak ditemukan. ' . $acs->lastError];
                break;
            }
            $idx  = max(1, (int) (isset($in['index']) ? $in['index'] : 1));
            $ssid = trim(isset($in['ssid']) ? $in['ssid'] : '');
            $pass = isset($in['pass']) ? (string) $in['pass'] : '';
            if ($pass !== '' && (strlen($pass) < 8 || strlen($pass) > 63)) {
                $r = ['ok' => false, 'msg' => 'Password WiFi harus 8–63 karakter.'];
                break;
            }
            if ($ssid !== '' && strlen($ssid) > 32) {
                $r = ['ok' => false, 'msg' => 'SSID maksimal 32 karakter.'];
                break;
            }
            $pv = [];
            if (isset($dev['InternetGatewayDevice'])) {
                $b = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.$idx";
                if ($ssid !== '') {
                    $pv[] = ["$b.SSID", $ssid, 'xsd:string'];
                }
                if ($pass !== '') {
                    if (acs_node($dev, "$b.PreSharedKey.1.KeyPassphrase")) {
                        $pp = "$b.PreSharedKey.1.KeyPassphrase";
                    } elseif (acs_node($dev, "$b.KeyPassphrase")) {
                        $pp = "$b.KeyPassphrase";
                    } else {
                        $pp = "$b.PreSharedKey.1.PreSharedKey";
                    }
                    $pv[] = [$pp, $pass, 'xsd:string'];
                }
            } else {
                if ($ssid !== '') {
                    $pv[] = ["Device.WiFi.SSID.$idx.SSID", $ssid, 'xsd:string'];
                }
                if ($pass !== '') {
                    $pv[] = ["Device.WiFi.AccessPoint.$idx.Security.KeyPassphrase", $pass, 'xsd:string'];
                }
            }
            if (!$pv) {
                $r = ['ok' => false, 'msg' => 'Isi SSID atau password terlebih dahulu.'];
                break;
            }
            $r = $acs->task($id, ['name' => 'setParameterValues', 'parameterValues' => $pv]);
            break;

        case 'tags_set':
            $dev = $acs->device($id);
            if (!$dev) {
                $r = ['ok' => false, 'msg' => 'Perangkat tidak ditemukan. ' . $acs->lastError];
                break;
            }
            $clean = function ($s) {
                $s = preg_replace('/\s+/', '_', trim((string) $s));
                return trim(preg_replace('/[^A-Za-z0-9_.\-]/', '', $s), '_');
            };
            $group = $clean(isset($in['area']) ? $in['area'] : '');
            $name  = $clean(isset($in['name']) ? $in['name'] : '');
            if ($group !== '' && $group === $name) {
                $r = ['ok' => false, 'msg' => 'Nama pelanggan tidak boleh sama dengan area.'];
                break;
            }
            if ($group !== '' && $name === '') {
                $r = ['ok' => false, 'msg' => 'Isi nama pelanggan jika area diisi.'];
                break;
            }
            $cur = isset($dev['_tags']) && is_array($dev['_tags']) ? array_values($dev['_tags']) : [];
            list(, , $rest) = tags_split($cur);
            $new = [];
            if ($group !== '') {
                $new[] = $group;
            }
            if ($name !== '') {
                $new[] = $name;
            }
            foreach ($rest as $t) {
                if (!in_array($t, $new, true)) {
                    $new[] = $t;
                }
            }
            if ($new === $cur) {
                $r = ['ok' => true, 'msg' => 'Tidak ada perubahan.'];
                break;
            }
            $okAll = true;
            foreach ($cur as $t) {
                if (!$acs->removeTag($id, $t)) {
                    $okAll = false;
                }
            }
            foreach ($new as $t) {
                if (!$acs->addTag($id, $t)) {
                    $okAll = false;
                }
            }
            $r = $okAll
                ? ['ok' => true, 'msg' => 'Area dan nama pelanggan disimpan.']
                : ['ok' => false, 'msg' => 'Sebagian tag gagal diproses. ' . $acs->lastError];
            break;

        case 'tag_add':
            $tag = preg_replace('/[^A-Za-z0-9_.\-]/', '_', trim(isset($in['tag']) ? $in['tag'] : ''));
            $r = ($tag !== '' && $acs->addTag($id, $tag))
                ? ['ok' => true, 'msg' => 'Tag ditambahkan.']
                : ['ok' => false, 'msg' => 'Gagal menambah tag. ' . $acs->lastError];
            break;

        case 'tag_del':
            $tag = isset($in['tag']) ? (string) $in['tag'] : '';
            $r = $acs->removeTag($id, $tag)
                ? ['ok' => true, 'msg' => 'Tag dihapus.']
                : ['ok' => false, 'msg' => 'Gagal menghapus tag. ' . $acs->lastError];
            break;

        case 'fault_del':
            $r = $acs->deleteFault($id)
                ? ['ok' => true, 'msg' => 'Fault dihapus.']
                : ['ok' => false, 'msg' => 'Gagal menghapus fault. ' . $acs->lastError];
            break;

        case 'fault_del_all':
            $n = 0;
            foreach ($acs->faults() as $f) {
                if ($acs->deleteFault($f['_id'])) {
                    $n++;
                }
            }
            $r = ['ok' => true, 'msg' => $n . ' fault dihapus.'];
            break;

        case 'location_save':
            $lat = isset($in['lat']) ? (float) $in['lat'] : 0;
            $lng = isset($in['lng']) ? (float) $in['lng'] : 0;
            if ($id === '' || abs($lat) > 90 || abs($lng) > 180) {
                $r = ['ok' => false, 'msg' => 'Koordinat tidak valid.'];
                break;
            }
            $r = location_set($id, round($lat, 6), round($lng, 6))
                ? ['ok' => true, 'msg' => 'Lokasi disimpan.']
                : ['ok' => false, 'msg' => 'Gagal menyimpan lokasi.'];
            break;

        case 'location_del':
            location_del($id);
            $r = ['ok' => true, 'msg' => 'Lokasi dihapus.'];
            break;

        case 'rxhist':
            $range = isset($in['range']) ? (string) $in['range'] : '7d';
            $r = ['ok' => true] + rx_series($id, $range);
            break;

        case 'rx_prov_install':
            $r = rx_provision_install($acs);
            break;

        case 'rx_prov_remove':
            $r = rx_provision_remove($acs);
            break;

        case 'rx_collect':
            $c = rx_collect($acs, $S);
            $r = $c['ok'] ? ['ok' => true, 'msg' => $c['devices'] . ' ONT dibaca, ' . $c['saved'] . ' titik redaman baru disimpan.'] : ['ok' => false, 'msg' => $c['error']];
            break;

        case 'test':
            $T = $S;
            if (isset($in['url']) && trim($in['url']) !== '') {
                $T['acs_url'] = rtrim(trim($in['url']), '/');
            }
            if (isset($in['user'])) {
                $T['acs_user'] = trim($in['user']);
            }
            if (!empty($in['clear'])) {
                $T['acs_pass'] = '';
            } elseif (isset($in['pass']) && $in['pass'] !== '') {
                $T['acs_pass'] = $in['pass'];
            }
            $tacs = new GenieACS($T);
            $res = $tacs->request('GET', '/devices/?projection=_id', null, $code);
            $r = ($code === 200 && is_array($res))
                ? ['ok' => true, 'msg' => 'Terhubung ke GenieACS NBI — ' . count($res) . ' perangkat terbaca.']
                : ['ok' => false, 'msg' => $tacs->lastError ?: ('Gagal, HTTP ' . $code)];
            break;
    }
    echo json_encode($r);
    exit;
}

/* ======================= SIMPAN SETTINGS ======================= */
$flash = '';
if ($page === 'settings' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals(csrf_token(), isset($_POST['csrf']) ? $_POST['csrf'] : '')) {
        $flash = 'err|Token tidak valid.';
    } else {
        $S['app_name']       = trim($_POST['app_name']) ?: 'Panel ACS';
        $S['acs_url']        = rtrim(trim($_POST['acs_url']), '/');
        $S['acs_user']       = trim($_POST['acs_user']);
        if ($_POST['acs_pass'] !== '') {
            $S['acs_pass'] = $_POST['acs_pass'];
        }
        if (!empty($_POST['acs_pass_clear'])) {
            $S['acs_pass'] = '';
        }
        $S['online_minutes'] = max(1, (int) $_POST['online_minutes']);
        $S['online_auto']    = !empty($_POST['online_auto']);
        $S['rx_good']        = (float) $_POST['rx_good'];
        $S['rx_fair']        = (float) $_POST['rx_fair'];
        $S['rx_keep_days']   = max(14, min(730, (int) $_POST['rx_keep_days']));
        $S['rx_drop_db']     = max(0.5, min(20, (float) $_POST['rx_drop_db']));
        $S['timezone']       = in_array($_POST['timezone'], timezone_identifiers_list(), true) ? $_POST['timezone'] : 'Asia/Makassar';
        $S['admin_user']     = trim($_POST['admin_user']) ?: 'admin';
        if ($_POST['admin_pass'] !== '') {
            if (strlen($_POST['admin_pass']) < 8) {
                $flash = 'err|Password admin minimal 8 karakter.';
            } else {
                $S['admin_pass'] = password_hash($_POST['admin_pass'], PASSWORD_DEFAULT);
            }
        }
        if ($flash === '') {
            $flash = save_settings($S) ? 'ok|Pengaturan disimpan.' : 'err|Gagal menyimpan (cek izin folder data).';
        }
    }
}

/* ======================= AMBIL DATA ======================= */
$acs   = new GenieACS($S);
$error = '';
$devs  = [];
$raw   = null;
$PR    = panel_routers();

if (in_array($page, ['dashboard', 'devices', 'mapping'], true)) {
    foreach ($acs->devices([], acs_list_projection()) as $d) {
        $devs[] = normalize_device($d, $S);
    }
    $error = $acs->lastError;
}
if ($PR['linked'] && $PR['error'] && $error === '') {
    $error = $PR['error'];
}

/* ======================= RENDER ======================= */
$titles = [
    'dashboard' => 'Dashboard', 'devices' => 'ONT Devices', 'device' => 'Detail Perangkat',
    'faults' => 'Faults', 'mapping' => 'Mapping', 'settings' => 'Settings',
];
if (!isset($titles[$page])) {
    $page = 'dashboard';
}
layout_start($S, $page, $titles[$page], $error, $flash);

switch ($page) {
    case 'dashboard':
        $faults = $acs->faults();
        page_dashboard($S, $devs, $faults);
        break;
    case 'devices':
        page_devices($S, $devs);
        break;
    case 'device':
        page_device($S, $acs, isset($_GET['id']) ? $_GET['id'] : '');
        break;
    case 'faults':
        page_faults($S, $acs);
        break;
    case 'mapping':
        page_mapping($S, $devs);
        break;
    case 'settings':
        page_settings($S);
        break;
}
layout_end();

/* =================================================================
 *  HELPER TAMPILAN
 * ================================================================= */

/** Favicon SVG (router + sinyal) dengan warna aksen panel. */
function fav_link()
{
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        . '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0ea5e9"/><stop offset="1" stop-color="#0369c7"/></linearGradient></defs>'
        . '<rect width="64" height="64" rx="14" fill="url(#g)"/>'
        . '<g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round">'
        . '<path d="M22 22a14 14 0 0 1 20 0"/><path d="M16 16a22 22 0 0 1 32 0"/><path d="M32 30v8"/></g>'
        . '<rect x="12" y="38" width="40" height="14" rx="4" fill="#fff"/>'
        . '<circle cx="21" cy="45" r="2.5" fill="#0369c7"/><circle cx="29" cy="45" r="2.5" fill="#0369c7"/></svg>';
    $uri = 'data:image/svg+xml,' . rawurlencode($svg);
    return '<link rel="icon" type="image/svg+xml" href="' . $uri . '">' . "\n" . '<link rel="apple-touch-icon" href="' . $uri . '">' . "\n" . '<meta name="theme-color" content="#0369c7">';
}

function icon($n)
{
    static $p = [
        'grid'     => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'router'   => '<rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 17.5h.01M10 17.5h.01M15 14V9M18.5 6.5a5 5 0 0 0-7 0M21 4a8.5 8.5 0 0 0-12 0"/>',
        'alert'    => '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
        'map'      => '<path d="M20 10c0 5-8 12-8 12s-8-7-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/>',
        'settings' => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
        'logout'   => '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
        'moon'     => '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
        'sun'      => '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
        'user'     => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
        'menu'     => '<path d="M4 6h16M4 12h16M4 18h16"/>',
        'wifi'     => '<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 20h.01"/>',
        'check'    => '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
        'xcircle'  => '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
        'pie'      => '<path d="M21.2 15.9A10 10 0 1 1 8 2.8"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>',
        'tag'      => '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L2 12V2h10l8.6 8.6a2 2 0 0 1 0 2.8z"/><circle cx="7" cy="7" r="1.5"/>',
        'clock'    => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'activity' => '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
        'signal'   => '<path d="M2 20h.01M7 20v-4M12 20v-8M17 20V8M22 4v16"/>',
        'refresh'  => '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>',
        'power'    => '<path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.8 0"/>',
        'list'     => '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
        'server'   => '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
        'users'    => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
        'plus'     => '<path d="M12 5v14M5 12h14"/>',
        'trash'    => '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
        'back'     => '<path d="M15 18l-6-6 6-6"/>',
        'plug'     => '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0V8zM12 18v4"/>',
        'save'     => '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8M7 3v5h8"/>',
        'layers'   => '<path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5M2 12l10 5 10-5"/>',
        'external' => '<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
        'edit'     => '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
        'locate'   => '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/><circle cx="12" cy="12" r="7"/>',
    ];
    return '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">' . (isset($p[$n]) ? $p[$n] : '') . '</svg>';
}

function nf($n)
{
    return number_format((float) $n, 0, ',', '.');
}

function wlan_off($e)
{
    return $e === false || $e === 0 || $e === '0' || (is_string($e) && strtolower($e) === 'false');
}

/** Potong teks maksimal $n karakter, sisanya "...", teks lengkap di tooltip. */
function cut15($s, $n = 15)
{
    $s = (string) $s;
    $mb = function_exists('mb_strlen');
    $len = $mb ? mb_strlen($s, 'UTF-8') : strlen($s);
    if ($len <= $n) {
        return h($s);
    }
    $part = $mb ? mb_substr($s, 0, $n, 'UTF-8') : substr($s, 0, $n);
    return '<span title="' . h($s) . '">' . h(rtrim($part)) . '...</span>';
}

function card_head($ic, $title, $extra = '')
{
    return '<div class="card-h"><span class="ti">' . icon($ic) . '</span><span class="ct">' . h($title) . '</span><span class="sp"></span>' . $extra . '</div>';
}

function rx_badge($rx, $rxc)
{
    if ($rx === null) {
        return '<span class="badge na">N/A</span>';
    }
    return '<span class="badge ' . $rxc . '">' . h(number_format($rx, 2, ',', '.')) . ' dBm</span>';
}

function status_dot($online)
{
    return $online ? '<span class="st on"><i></i>Online</span>' : '<span class="st off"><i></i>Offline</span>';
}

function dev_link($id, $text)
{
    return '<a href="?page=device&id=' . rawurlencode($id) . '">' . h($text) . '</a>';
}

/* =================================================================
 *  HALAMAN
 * ================================================================= */

/** Baris grafik batang horizontal. $label & $hint harus sudah di-escape. */
function bar_row($label, $hint, $val, $pct, $color)
{
    return '<div class="bl-row"><div class="bl-top"><span class="bl-name"><i style="background:' . $color . '"></i>' . $label
        . ($hint !== '' ? ' <em>' . $hint . '</em>' : '') . '</span><span class="bl-val"><b>' . $val . '</b><small>' . $pct . '%</small></span></div>'
        . '<div class="bl-bar"><i style="width:' . $pct . '%;background:' . $color . '"></i></div></div>';
}

function page_dashboard($S, $devs, $faults)
{
    // filter profile (default: semua)
    $grpSel = isset($_GET['grp']) ? (string) $_GET['grp'] : '';
    $grpList = [];
    $noneN = 0;
    foreach ($devs as $d) {
        if ($d['group'] === '') {
            $noneN++;
        } else {
            $grpList[$d['group']] = (isset($grpList[$d['group']]) ? $grpList[$d['group']] : 0) + 1;
        }
    }
    uksort($grpList, 'strnatcasecmp');
    if ($grpSel !== '') {
        $devs = array_values(array_filter($devs, function ($d) use ($grpSel) {
            return $grpSel === '__none' ? $d['group'] === '' : $d['group'] === $grpSel;
        }));
        $ids = array_flip(array_column($devs, 'id'));
        $faults = array_values(array_filter($faults, function ($f) use ($ids) {
            return isset($f['device']) && isset($ids[$f['device']]);
        }));
    }

    $total = count($devs);
    $online = 0;
    $clients = 0;
    $rx = ['good' => 0, 'fair' => 0, 'poor' => 0, 'na' => 0];
    $rxSum = 0;
    $rxN = 0;
    $br = [];
    $pc = [];
    $prof = [];
    $week = time() - 7 * 86400;
    $ev = ['boot' => 0, 'bootstrap' => 0, 'new' => 0];
    foreach ($devs as $d) {
        if ($d['online']) {
            $online++;
        }
        $rx[$d['rxc']]++;
        if ($d['rx'] !== null) {
            $rxSum += $d['rx'];
            $rxN++;
        }
        $clients += (int) $d['clients'];
        $br[$d['brand']] = (isset($br[$d['brand']]) ? $br[$d['brand']] : 0) + 1;
        $pc[$d['pc']] = 1;
        $gk = $d['group'] !== '' ? $d['group'] : '__none';
        if (!isset($prof[$gk])) {
            $prof[$gk] = ['n' => 0, 'on' => 0];
        }
        $prof[$gk]['n']++;
        if ($d['online']) {
            $prof[$gk]['on']++;
        }
        if ($d['lastBoot'] >= $week) {
            $ev['boot']++;
        }
        if ($d['bootstrap'] >= $week) {
            $ev['bootstrap']++;
        }
        if ($d['registered'] >= $week) {
            $ev['new']++;
        }
    }
    arsort($br);
    uksort($prof, function ($a, $b) {
        if ($a === '__none') {
            return 1;
        }
        if ($b === '__none') {
            return -1;
        }
        return strnatcasecmp($a, $b);
    });
    $offline = $total - $online;
    $pct = function ($n) use ($total) {
        return $total ? (int) round($n / $total * 100) : 0;
    };
    $rxAvg = $rxN ? number_format($rxSum / $rxN, 2, ',', '.') : '-';

    $att = array_values(array_filter($devs, function ($d) {
        return !$d['online'] || $d['rxc'] === 'poor';
    }));
    usort($att, function ($a, $b) {
        if ($a['online'] !== $b['online']) {
            return $a['online'] ? 1 : -1;
        }
        return ($a['rx'] === null ? 0 : $a['rx']) <=> ($b['rx'] === null ? 0 : $b['rx']);
    });
    $attN = count($att);
    $att = array_slice($att, 0, 8);

    $recent = $devs;
    usort($recent, function ($a, $b) {
        return $b['registered'] - $a['registered'];
    });
    $recent = array_slice($recent, 0, 6);

    $palette = ['#0369c7', '#059669', '#d97706', '#7c3aed', '#0891b2', '#db2777', '#65a30d', '#475569'];
    $grpLabel = $grpSel === '' ? 'Semua router' : ($grpSel === '__none' ? 'Tanpa router' : 'Router ' . $grpSel);
    ?>
    <div class="dash-head">
        <div>
            <h2 class="dh-title">Ringkasan Jaringan</h2>
            <div class="dh-sub"><?= h($grpLabel) ?> · data per <?= date('d M Y, H:i') ?> <?= h(date('T')) ?></div>
        </div>
        <div class="dh-actions">
            <label class="grp-pick" title="Filter router">
                <?= icon('layers') ?>
                <select aria-label="Filter router" onchange="location.href='?page=dashboard'+(this.value?'&grp='+encodeURIComponent(this.value):'')">
                    <option value="">Semua Router (<?= nf($noneN + array_sum($grpList)) ?>)</option>
                    <?php foreach ($grpList as $g => $c): ?><option value="<?= h($g) ?>" <?= $grpSel === (string) $g ? 'selected' : '' ?>><?= h($g) ?> (<?= nf($c) ?>)</option><?php endforeach; ?>
                    <option value="__none" <?= $grpSel === '__none' ? 'selected' : '' ?>>Tanpa router (<?= nf($noneN) ?>)</option>
                </select>
            </label>
            <button class="btn" onclick="location.reload()"><?= icon('refresh') ?>Muat Ulang</button>
        </div>
    </div>

    <div class="kpis">
        <a class="kpi" href="?page=devices">
            <div class="k-head"><span class="k-ico blue"><?= icon('router') ?></span><span class="k-lbl">Total ONT</span></div>
            <div class="k-val"><?= nf($total) ?></div>
            <div class="k-meter"><i class="blue" style="width:<?= $total ? 100 : 0 ?>%"></i></div>
            <div class="k-sub"><span><?= nf(count($br)) ?> merek · <?= nf(count($pc)) ?> model</span><span><?= nf($clients) ?> klien WiFi</span></div>
        </a>
        <a class="kpi" href="?page=devices&status=online">
            <div class="k-head"><span class="k-ico green"><?= icon('check') ?></span><span class="k-lbl">Online</span><span class="k-pct ok"><?= $pct($online) ?>%</span></div>
            <div class="k-val"><?= nf($online) ?></div>
            <div class="k-meter"><i class="ok" style="width:<?= $pct($online) ?>%"></i></div>
            <div class="k-sub"><span>dari <?= nf($total) ?> ONT</span></div>
        </a>
        <a class="kpi" href="?page=devices&status=offline">
            <div class="k-head"><span class="k-ico red"><?= icon('xcircle') ?></span><span class="k-lbl">Offline</span><span class="k-pct bad"><?= $pct($offline) ?>%</span></div>
            <div class="k-val"><?= nf($offline) ?></div>
            <div class="k-meter"><i class="bad" style="width:<?= $pct($offline) ?>%"></i></div>
            <div class="k-sub"><span>dari <?= nf($total) ?> ONT</span></div>
        </a>
        <a class="kpi" href="?page=devices">
            <div class="k-head"><span class="k-ico amber"><?= icon('signal') ?></span><span class="k-lbl">Rata-rata Redaman</span></div>
            <div class="k-val"><?= $rxAvg ?><small><?= $rxN ? ' dBm' : '' ?></small></div>
            <div class="k-meter seg">
                <i class="ok" style="width:<?= $pct($rx['good']) ?>%"></i><i class="warn" style="width:<?= $pct($rx['fair']) ?>%"></i><i class="bad" style="width:<?= $pct($rx['poor']) ?>%"></i>
            </div>
            <div class="k-sub"><span><?= nf($rx['poor']) ?> ONT redaman tinggi</span></div>
        </a>
    </div>

    <div class="dgrid3">
        <div class="card">
            <?= card_head('signal', 'Kualitas Sinyal') ?>
            <div class="blist">
                <?= bar_row('Bagus', '&ge; ' . h($S['rx_good']) . ' dBm', nf($rx['good']), $pct($rx['good']), 'var(--ok)') ?>
                <?= bar_row('Cukup', h($S['rx_fair']) . ' s/d ' . h($S['rx_good']) . ' dBm', nf($rx['fair']), $pct($rx['fair']), 'var(--warn)') ?>
                <?= bar_row('Buruk', '&lt; ' . h($S['rx_fair']) . ' dBm', nf($rx['poor']), $pct($rx['poor']), 'var(--bad)') ?>
                <?= bar_row('Tidak terbaca', '', nf($rx['na']), $pct($rx['na']), 'var(--line2)') ?>
            </div>
        </div>
        <div class="card">
            <?= card_head('router', 'Merek ONT', '<span class="chip">' . nf(count($br)) . ' merek</span>') ?>
            <div class="blist">
                <?php $i = 0; foreach ($br as $b => $c): ?>
                    <?= bar_row(h($b), '', nf($c), $pct($c), $palette[$i++ % count($palette)]) ?>
                <?php endforeach; if (!$br): ?><div class="bl-empty">Belum ada data</div><?php endif; ?>
            </div>
        </div>
        <div class="card">
            <?= card_head('layers', 'Status per Router') ?>
            <div class="blist">
                <?php foreach ($prof as $g => $c):
                    $pp = $c['n'] ? (int) round($c['on'] / $c['n'] * 100) : 0; ?>
                    <?= bar_row($g === '__none' ? '<span class="muted">Tanpa router</span>' : h($g), 'online', nf($c['on']) . ' / ' . nf($c['n']), $pp, $pp >= 90 ? 'var(--ok)' : ($pp >= 60 ? 'var(--warn)' : 'var(--bad)')) ?>
                <?php endforeach; if (!$prof): ?><div class="bl-empty">Belum ada data</div><?php endif; ?>
            </div>
        </div>
    </div>

    <div class="dgrid2">
        <div class="card">
            <?= card_head('alert', 'Perlu Perhatian', '<span class="chip">' . nf($attN) . ' ONT</span>') ?>
            <div class="scroll">
            <table class="tbl">
                <thead><tr><th>Nama</th><th>Router</th><th>Masalah</th><th class="r">Redaman</th><th>Komunikasi Terakhir</th></tr></thead>
                <tbody>
                <?php foreach ($att as $d): ?>
                    <tr>
                        <td class="nowrap"><a class="nm<?= $d['name'] === '' ? ' none' : '' ?>" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><span class="led <?= $d['online'] ? 'on' : 'off' ?>"></span><?= $d['name'] !== '' ? cut15($d['name']) : cut15($d['serial']) ?></a></td>
                        <td class="nowrap"><?= $d['group'] !== '' ? cut15($d['group']) : '<span class="muted">-</span>' ?></td>
                        <td class="nowrap"><?= !$d['online'] ? '<span class="badge poor">Offline</span> ' : '' ?><?= $d['rxc'] === 'poor' ? '<span class="badge fair">Redaman tinggi</span>' : '' ?></td>
                        <td class="r nowrap"><?= rx_badge($d['rx'], $d['rxc']) ?></td>
                        <td class="nowrap"><?= ago($d['last']) ?></td>
                    </tr>
                <?php endforeach; if (!$att): ?>
                    <tr><td colspan="5" class="empty">Semua ONT dalam kondisi normal</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
            </div>
            <?php if ($attN > count($att)): ?><div class="card-foot"><a href="?page=devices&status=offline">Lihat semua di ONT Devices →</a></div><?php endif; ?>
        </div>
        <?php
        $dl = rx_delta24();
        $drop = (float) $S['rx_drop_db'];
        $worse = [];
        foreach ($devs as $d) {
            if (isset($dl[$d['id']]) && $dl[$d['id']] <= -$drop) {
                $d['delta'] = $dl[$d['id']];
                $worse[] = $d;
            }
        }
        usort($worse, function ($a, $b) { return $a['delta'] <=> $b['delta']; });
        ?>
        <div class="card">
            <?= card_head('signal', 'Redaman Memburuk (24 jam)', '<span class="chip">' . nf(count($worse)) . ' ONT</span>') ?>
            <div class="scroll">
            <table class="tbl">
                <thead><tr><th>Nama</th><th>Router</th><th class="r">Redaman</th><th class="r">Perubahan</th></tr></thead>
                <tbody>
                <?php foreach (array_slice($worse, 0, 8) as $d): ?>
                    <tr>
                        <td class="nowrap"><a class="nm<?= $d['name'] === '' ? ' none' : '' ?>" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><span class="led <?= $d['online'] ? 'on' : 'off' ?>"></span><?= $d['name'] !== '' ? cut15($d['name']) : cut15($d['serial']) ?></a></td>
                        <td class="nowrap"><?= $d['group'] !== '' ? cut15($d['group']) : '<span class="muted">-</span>' ?></td>
                        <td class="r nowrap"><?= rx_badge($d['rx'], $d['rxc']) ?></td>
                        <td class="r nowrap"><?= delta_badge($d['delta'], $S) ?></td>
                    </tr>
                <?php endforeach; if (!$worse): ?>
                    <tr><td colspan="4" class="empty">Tidak ada ONT yang redamannya turun ≥ <?= h(rtrim(rtrim(number_format($drop, 1, ',', ''), '0'), ',')) ?> dB dalam 24 jam</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
            </div>
        </div>
        <div class="card">
            <?= card_head('activity', '7 Hari Terakhir') ?>
            <dl class="kvl">
                <div><dt>ONT restart</dt><dd><?= nf($ev['boot']) ?></dd></div>
                <div><dt>ONT reset / pasang ulang</dt><dd><?= nf($ev['bootstrap']) ?></dd></div>
                <div><dt>ONT baru terdaftar</dt><dd><?= nf($ev['new']) ?></dd></div>
                <div><dt>Fault aktif</dt><dd><?= count($faults) ? '<a href="?page=faults">' . nf(count($faults)) . '</a>' : '0' ?></dd></div>
                <div><dt>Klien WiFi terhubung</dt><dd><?= nf($clients) ?></dd></div>
            </dl>
        </div>
    </div>

    <div class="card">
        <?= card_head('list', 'ONT Baru Terdaftar', '<a class="btn sm" href="?page=devices">Lihat Semua</a>') ?>
        <div class="scroll">
        <table class="tbl">
            <thead><tr><th>Nama</th><th>SN</th><th>Model</th><th>Router</th><th>Status</th><th>Terdaftar</th></tr></thead>
            <tbody>
            <?php foreach ($recent as $d): ?>
                <tr>
                    <td class="nowrap"><a class="nm<?= $d['name'] === '' ? ' none' : '' ?>" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><?= $d['name'] !== '' ? cut15($d['name']) : 'Tanpa nama' ?></a></td>
                    <td class="nowrap"><?= $d['group'] !== '' ? cut15($d['group']) : '<span class="muted">-</span>' ?><?php if ($d['area'] !== ''): ?><div class="muted small"><?= cut15($d['area']) ?></div><?php endif; ?></td>
                    <td class="mono nowrap"><a class="sn" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><?= cut15($d['serial']) ?></a></td>
                    <td class="nowrap"><?= cut15($d['pc']) ?></td>
                    <td class="nowrap"><?= $d['group'] !== '' ? cut15($d['group']) : '<span class="muted">-</span>' ?></td>
                    <td><?= status_dot($d['online']) ?></td>
                    <td class="nowrap"><?= $d['registered'] ? date('d M Y, H:i', $d['registered']) : '-' ?></td>
                </tr>
            <?php endforeach; if (!$recent): ?>
                <tr><td colspan="6" class="empty">Tidak ada perangkat</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php
}

function page_devices($S, $devs)
{
    $dl = rx_delta24();
    usort($devs, function ($a, $b) {
        if (($a['name'] === '') !== ($b['name'] === '')) {
            return $a['name'] === '' ? 1 : -1;
        }
        return strnatcasecmp($a['name'] !== '' ? $a['name'] : $a['serial'], $b['name'] !== '' ? $b['name'] : $b['serial']);
    });
    $status = isset($_GET['status']) ? $_GET['status'] : '';
    $models = array_unique(array_column($devs, 'pc'));
    sort($models);
    $groups = [];
    foreach ($devs as $d) {
        if ($d['group'] !== '') {
            $groups[$d['group']] = (isset($groups[$d['group']]) ? $groups[$d['group']] : 0) + 1;
        }
    }
    uksort($groups, 'strnatcasecmp');
    ?>
    <div class="card">
        <?= card_head('router', 'ONT Devices', '<span class="chip" id="countInfo">' . nf(count($devs)) . ' perangkat</span>') ?>
        <div class="filters">
            <input type="search" id="q" placeholder="Cari nama, SN, IP, SSID...">
            <select id="fGroup">
                <option value="">Semua router</option>
                <?php foreach ($groups as $g => $c): ?><option value="<?= h($g) ?>"><?= h($g) ?> (<?= (int) $c ?>)</option><?php endforeach; ?>
                <option value="__none">Tanpa router</option>
            </select>
            <select id="fStatus">
                <option value="">Semua status</option>
                <option value="online" <?= $status === 'online' ? 'selected' : '' ?>>Online</option>
                <option value="offline" <?= $status === 'offline' ? 'selected' : '' ?>>Offline</option>
            </select>
            <select id="fRx">
                <option value="">Semua RX</option>
                <option value="good">Excellent</option>
                <option value="fair">Fair</option>
                <option value="poor">Poor</option>
                <option value="na">N/A</option>
                <option value="worse">Memburuk 24 jam</option>
            </select>
            <select id="fModel">
                <option value="">Semua model</option>
                <?php foreach ($models as $m): ?><option><?= h($m) ?></option><?php endforeach; ?>
            </select>
        </div>
        <div class="scroll">
        <table class="tbl" id="devTable">
            <thead><tr>
                <th class="r">No</th><th>Nama</th><th>Router</th><th>SN</th><th>Model</th><th>IP TR-069</th>
                <th>SSID</th><th class="r">Klien</th><th class="r">RX</th><th class="r">Δ 24 jam</th><th class="r">Suhu</th><th>Komunikasi Terakhir</th><th>Up / Down</th>
            </tr></thead>
            <tbody>
            <?php $no = 0; foreach ($devs as $d): $no++;
                $search = strtolower(implode(' ', [$d['id'], $d['serial'], $d['pc'], $d['name'], $d['group'], $d['area'], $d['pppoe'], $d['ip'], $d['ip_pppoe'], $d['ssid'], $d['ssid5'], implode(' ', $d['tags'])]));
                $dv = isset($dl[$d['id']]) ? $dl[$d['id']] : null; ?>
                <tr data-s="<?= h($search) ?>" data-st="<?= $d['online'] ? 'online' : 'offline' ?>" data-rx="<?= $d['rxc'] ?><?= $dv !== null && $dv <= -(float) $S['rx_drop_db'] ? ' worse' : '' ?>" data-m="<?= h($d['pc']) ?>" data-g="<?= h($d['group'] !== '' ? $d['group'] : '__none') ?>">
                    <td class="r muted no"><?= $no ?></td>
                    <td class="nowrap"><a class="nm<?= $d['name'] === '' ? ' none' : '' ?>" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><span class="led <?= $d['online'] ? 'on' : 'off' ?>" title="<?= $d['online'] ? 'Online' : 'Offline' ?>"></span><?= $d['name'] !== '' ? cut15($d['name']) : 'Tanpa nama' ?></a></td>
                    <td class="mono nowrap"><a class="sn" href="?page=device&id=<?= rawurlencode($d['id']) ?>"><?= cut15($d['serial']) ?></a></td>
                    <td class="nowrap"><?= cut15($d['pc']) ?></td>
                    <td class="mono nowrap"><?= ip_link($d['ip']) ?></td>
                    <td class="nowrap"><?= $d['ssid'] !== '' ? cut15($d['ssid']) : ($d['ssid5'] !== '' ? cut15($d['ssid5']) : '-') ?><?php if ($d['ssid5'] !== ''): ?><span class="band b5 mini" title="5 GHz: <?= h($d['ssid5']) ?>">5G</span><?php endif; ?></td>
                    <td class="r"><?= $d['clients'] === null ? '-' : (int) $d['clients'] ?></td>
                    <td class="r nowrap"><?= rx_badge($d['rx'], $d['rxc']) ?></td>
                    <td class="r nowrap"><?= delta_badge($dv, $S) ?></td>
                    <td class="r nowrap"><?= $d['temp'] !== null ? cut15($d['temp'] . '°C') : '-' ?></td>
                    <td class="nowrap" title="<?= $d['last'] ? date('Y-m-d H:i:s', $d['last']) : '' ?>"><?= cut15(ago($d['last'])) ?></td>
                    <td class="nowrap"><?= updown($d) ?></td>
                </tr>
            <?php endforeach; if (!$devs): ?>
                <tr><td colspan="13" class="empty">Tidak ada perangkat</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
    <script>
    (function () {
        var q = document.getElementById('q'), st = document.getElementById('fStatus'),
            rx = document.getElementById('fRx'), md = document.getElementById('fModel'), gp = document.getElementById('fGroup'),
            rows = document.querySelectorAll('#devTable tbody tr[data-s]'), info = document.getElementById('countInfo');
        function apply() {
            var t = q.value.toLowerCase().trim(), n = 0;
            rows.forEach(function (r) {
                var ok = (!t || r.dataset.s.indexOf(t) > -1) && (!st.value || r.dataset.st === st.value)
                    && (!rx.value || r.dataset.rx.split(' ').indexOf(rx.value) > -1) && (!md.value || r.dataset.m === md.value)
                    && (!gp.value || r.dataset.g === gp.value);
                r.style.display = ok ? '' : 'none';
                if (ok) {
                    n++;
                    r.querySelector('.no').textContent = n;
                }
            });
            info.textContent = n.toLocaleString('id-ID') + ' perangkat';
        }
        [q, gp, st, rx, md].forEach(function (el) { el.addEventListener('input', apply); });
        apply();
    })();
    </script>
    <?php
}

function page_device($S, $acs, $id)
{
    global $G;
    $raw = $id !== '' ? $acs->device($id) : null;
    if (!$raw) {
        echo '<div class="alert err">Perangkat tidak ditemukan. ' . h($acs->lastError) . '</div>';
        return;
    }
    $d = normalize_device($raw, $S);
    $tg = ip_target($d['ip']);
    $loc = locations_all();
    $PRl = panel_routers()['linked'];
    $panelUrl = isset(panel_routers()['panel']['url']) ? rtrim(panel_routers()['panel']['url'], '/') : '';

    // Daftar WLAN
    $wlans = [];
    $wl = acs_node($raw, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration');
    $wmax = 0;
    if (is_array($wl)) {
        foreach ($wl as $k => $w) {
            if (is_array($w) && ((string) $k)[0] !== '_') {
                $wmax = max($wmax, (int) $k);
            }
        }
    }
    if (is_array($wl)) {
        foreach ($wl as $k => $w) {
            if (!is_array($w) || ((string) $k)[0] === '_') {
                continue;
            }
            $wlans[] = [
                'idx' => $k,
                'ssid' => isset($w['SSID']['_value']) ? $w['SSID']['_value'] : '-',
                'enable' => isset($w['Enable']['_value']) ? $w['Enable']['_value'] : null,
                'channel' => isset($w['Channel']['_value']) ? $w['Channel']['_value'] : '-',
                'std' => isset($w['Standard']['_value']) ? $w['Standard']['_value'] : '-',
                'clients' => wlan_assoc($w) === null ? '-' : wlan_assoc($w),
                'band' => wlan_band($k, $w, $wmax),
                'sec' => isset($w['BeaconType']['_value']) && $w['BeaconType']['_value'] !== '' ? $w['BeaconType']['_value'] : '-',
                'hidden' => isset($w['SSIDAdvertisementEnabled']['_value']) ? wlan_off($w['SSIDAdvertisementEnabled']['_value']) : null,
                'power' => isset($w['TransmitPower']['_value']) && $w['TransmitPower']['_value'] !== '' ? $w['TransmitPower']['_value'] . '%' : '-',
            ];
        }
    }
    $ws = acs_node($raw, 'Device.WiFi.SSID');
    if (is_array($ws)) {
        foreach ($ws as $k => $w) {
            if (!is_array($w) || ((string) $k)[0] === '_') {
                continue;
            }
            $wlans[] = [
                'idx' => $k,
                'ssid' => isset($w['SSID']['_value']) ? $w['SSID']['_value'] : '-',
                'enable' => isset($w['Enable']['_value']) ? $w['Enable']['_value'] : null,
                'channel' => '-', 'std' => '-', 'sec' => '-', 'hidden' => null, 'power' => '-',
                'band' => wlan_band($k, $w, count($ws)),
                'clients' => acs_get($raw, "Device.WiFi.AccessPoint.$k.AssociatedDeviceNumberOfEntries") ?: '-',
            ];
        }
    }

    // Daftar host / klien LAN
    $hosts = [];
    $hn = acs_node($raw, 'InternetGatewayDevice.LANDevice.1.Hosts.Host');
    if (!is_array($hn)) {
        $hn = acs_node($raw, 'Device.Hosts.Host');
    }
    if (is_array($hn)) {
        foreach ($hn as $k => $hst) {
            if (!is_array($hst) || ((string) $k)[0] === '_') {
                continue;
            }
            $hosts[] = [
                'name' => isset($hst['HostName']['_value']) ? $hst['HostName']['_value'] : '-',
                'ip' => isset($hst['IPAddress']['_value']) ? $hst['IPAddress']['_value'] : '-',
                'mac' => isset($hst['MACAddress']['_value']) ? $hst['MACAddress']['_value'] : (isset($hst['PhysAddress']['_value']) ? $hst['PhysAddress']['_value'] : '-'),
                'iface' => isset($hst['InterfaceType']['_value']) ? $hst['InterfaceType']['_value'] : (isset($hst['Layer2Interface']['_value']) ? $hst['Layer2Interface']['_value'] : '-'),
                'active' => isset($hst['Active']['_value']) ? $hst['Active']['_value'] : null,
            ];
        }
    }

    // FiberHome: Hosts kosong -> pakai daftar klien WiFi (AssociatedDevice)
    if (!$hosts && is_array($wl)) {
        foreach ($wl as $k => $w) {
            if (!is_array($w) || ((string) $k)[0] === '_' || !isset($w['AssociatedDevice']) || !is_array($w['AssociatedDevice'])) {
                continue;
            }
            foreach ($w['AssociatedDevice'] as $ak => $a) {
                if (!is_array($a) || ((string) $ak)[0] === '_' || empty($a['AssociatedDeviceMACAddress']['_value'])) {
                    continue;
                }
                $hosts[] = [
                    'name' => '-',
                    'ip' => !empty($a['AssociatedDeviceIPAddress']['_value']) ? $a['AssociatedDeviceIPAddress']['_value'] : '-',
                    'mac' => $a['AssociatedDeviceMACAddress']['_value'],
                    'iface' => 'WiFi ' . (isset($w['SSID']['_value']) ? $w['SSID']['_value'] : $k),
                    'active' => true,
                ];
            }
        }
    }

    // Koneksi WAN
    $wans = [];
    $wcd = acs_node($raw, 'InternetGatewayDevice.WANDevice.1.WANConnectionDevice');
    if (is_array($wcd)) {
        foreach ($wcd as $ci => $c) {
            if (!is_array($c) || ((string) $ci)[0] === '_') {
                continue;
            }
            foreach (['WANIPConnection' => 'IP', 'WANPPPConnection' => 'PPPoE'] as $ot => $lbl) {
                if (!isset($c[$ot]) || !is_array($c[$ot])) {
                    continue;
                }
                foreach ($c[$ot] as $wi => $x) {
                    if (!is_array($x) || ((string) $wi)[0] === '_') {
                        continue;
                    }
                    $g = function ($p) use ($x) {
                        return isset($x[$p]['_value']) ? $x[$p]['_value'] : null;
                    };
                    $wname = (string) $g('Name');
                    $wtype = (string) $g('ConnectionType');
                    $vlan = null;
                    foreach (['X_FH_VlanID', 'X_FH_VLANID', 'X_CT-COM_VLANIDMark', 'X_CMCC_VLANIDMark', 'X_HW_VLAN', 'X_ZTE-COM_VLANID', 'VLANID'] as $vk) {
                        if ($g($vk) !== null && $g($vk) !== '') {
                            $vlan = $g($vk);
                            break;
                        }
                    }
                    if ($vlan === null && preg_match('/VID_?(\d+)/i', $wname, $m)) {
                        $vlan = $m[1];
                    }
                    $wans[] = [
                        'name' => $wname !== '' ? $wname : $ot . '.' . $wi,
                        'proto' => $lbl,
                        'mode' => stripos($wtype, 'bridg') !== false ? 'Bridge' : ($wtype !== '' ? 'Route' : '-'),
                        'type' => $wtype !== '' ? $wtype : '-',
                        'vlan' => $vlan !== null ? $vlan : '-',
                        'ip' => (string) $g('ExternalIPAddress') !== '' ? (string) $g('ExternalIPAddress') : '-',
                        'user' => (string) $g('Username'),
                        'enable' => $g('Enable'),
                        'status' => (string) $g('ConnectionStatus'),
                        'uptime' => $g('Uptime'),
                    ];
                }
            }
        }
    }

    $lok = isset($loc[$d['id']]) ? $loc[$d['id']]['lat'] . ', ' . $loc[$d['id']]['lng'] : 'Belum diset';
    $sec = [
        ['router', 'Perangkat', [
            'Serial Number' => $d['serial'],
            'Model' => $d['pc'],
            'Merek' => $d['brand'],
            'Software' => $d['sw'] ?: '-',
            'Hardware' => $d['hw'] ?: '-',
            'OUI' => $d['oui'],
            'Device ID' => $d['id'],
        ]],
        ['server', 'Jaringan', [
            'IP TR-069' => $d['ip'] ?: '-',
            'Akses Web' => $tg ? ['<a class="iplink" href="' . h($tg['url']) . '" target="_blank" rel="noopener">' . h($tg['url']) . '</a>'] : '-',
            'Username PPPoE' => $d['pppoe'] ?: '-',
            'IP PPPoE' => $d['ip_pppoe'] ?: '-',
            'MAC ONT' => $d['mac'] ?: '-',
            'Mode PON' => $d['ponmode'] ?: '-',
            'SSID' => trim(($d['ssid'] ?: '') . ($d['ssid5'] !== '' ? ' / ' . $d['ssid5'] . ' (5G)' : '')) ?: '-',
        ]],
        ['clock', 'Waktu & Status', [
            'Uptime ONT' => fmt_uptime($d['uptime']),
            'Uptime PPPoE' => $d['pppuptime'] ?: '-',
            'Komunikasi Terakhir' => $d['last'] ? date('d M Y, H:i:s', $d['last']) : '-',
            'Interval Laporan' => $d['inform_iv'] ? $d['inform_iv'] . ' detik' : '-',
            'Restart Terakhir' => ($d['lastBoot'] ?: $d['boot']) ? date('d M Y, H:i', $d['lastBoot'] ?: $d['boot']) : '-',
            'Terdaftar' => $d['registered'] ? date('d M Y, H:i', $d['registered']) : '-',
            'Lokasi' => $lok,
        ]],
    ];
    $kvCopy = ['Serial Number', 'Device ID', 'OUI', 'IP TR-069', 'Username PPPoE', 'IP PPPoE', 'MAC ONT', 'SSID'];
    $kvMono = ['Serial Number', 'Software', 'Hardware', 'OUI', 'Device ID', 'IP TR-069', 'Akses Web', 'Username PPPoE', 'IP PPPoE', 'MAC ONT'];
    $rxTxt = ['good' => 'Bagus', 'fair' => 'Cukup', 'poor' => 'Buruk', 'na' => 'Tidak terbaca'];
    ?>
    <div class="card">
        <div class="dev-head">
            <div class="dh-left">
                <span class="tile big <?= $d['online'] ? 'on' : 'off' ?>"><?= icon('router') ?></span>
                <div>
                    <a class="back" href="?page=devices"><?= icon('back') ?>ONT Devices</a>
                    <h2><?= h($d['name'] !== '' ? $d['name'] : 'Tanpa nama') ?></h2>
                    <div class="dh-meta">
                        <span class="mono"><?= h($d['serial']) ?></span><span>·</span><span><?= h($d['pc']) ?></span><span>·</span><span><?= h($d['brand']) ?></span>
                        <?php if ($d['group'] !== ''): ?><?php if ($d['router_id'] !== '' && $panelUrl): ?><a class="tag g" href="<?= h($panelUrl . '/#/router/' . $d['router_id']) ?>" target="_blank" rel="noopener" title="Buka router di panel utama"><?= h($d['group']) ?><?= $d['router_on'] === false ? ' · VPN terputus' : '' ?></a><?php else: ?><span class="tag g"><?= h($d['group']) ?></span><?php endif; ?><?php endif; ?>
                        <?php if ($d['area'] !== ''): ?><span class="tag"><?= h($d['area']) ?></span><?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="btns">
                <?php if ($tg): ?><a class="btn" href="<?= h($tg['url']) ?>" target="_blank" rel="noopener" title="<?= h($tg['url']) ?>"><?= icon('external') ?>Buka Web ONT</a><?php endif; ?>
                <button class="btn" onclick="act('refresh',{id:DEV,tr181:<?= $d['tr181'] ? 'true' : 'false' ?>},true)"><?= icon('refresh') ?>Refresh</button>
                <button class="btn danger" onclick="if(confirm('Reboot perangkat ini?'))act('reboot',{id:DEV})"><?= icon('power') ?>Reboot</button>
            </div>
        </div>
        <div class="dev-stats">
            <div class="ds"><span>Status</span><b><?= status_dot($d['online']) ?></b><small><?= ago($d['last']) ?></small></div>
            <div class="ds"><span>Redaman</span><b><?= rx_badge($d['rx'], $d['rxc']) ?></b><small><?= $rxTxt[$d['rxc']] ?></small></div>
            <div class="ds"><span>Suhu</span><b><?= $d['temp'] !== null ? h($d['temp']) . ' °C' : '-' ?></b><small>Transceiver</small></div>
            <div class="ds"><span>Uptime</span><b><?= h(fmt_uptime($d['uptime'])) ?></b><small>Sejak restart</small></div>
            <div class="ds"><span>Klien WiFi</span><b><?= $d['clients'] === null ? '-' : (int) $d['clients'] ?></b><small>Perangkat terhubung</small></div>
            <div class="ds"><span>IP TR-069</span><b class="mono"><?= $d['ip'] !== '' ? ip_link($d['ip']) : '-' ?></b><small>Klik untuk buka web</small></div>
        </div>
    </div>

    <div class="card rxh">
        <?= card_head('activity', 'History Redaman', '<span class="seg" id="rxRange"><button data-r="1d">24 jam</button><button data-r="7d" class="on">7 hari</button><button data-r="30d">30 hari</button><button data-r="90d">90 hari</button></span>') ?>
        <div class="rx-stats" id="rxStats"></div>
        <div class="rx-wrap"><canvas id="rxChart"></canvas><div class="rx-empty muted" id="rxEmpty" hidden></div></div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var GOOD = <?= json_encode((float) $S['rx_good']) ?>, FAIR = <?= json_encode((float) $S['rx_fair']) ?>, chart = null;
        function fmt(t, long) { var d = new Date(t * 1000); var p = function (n) { return (n < 10 ? '0' : '') + n; };
            return long ? p(d.getDate()) + '/' + p(d.getMonth() + 1) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) : p(d.getHours()) + ':' + p(d.getMinutes()); }
        function load(r) {
            document.querySelectorAll('#rxRange button').forEach(function (b) { b.classList.toggle('on', b.dataset.r === r); });
            api('rxhist', {id: DEV, range: r}).then(function (res) {
                var pts = res.points || [], st = res.stats, el = document.getElementById('rxEmpty');
                document.getElementById('rxStats').innerHTML = st
                    ? '<span>Terendah <b>' + st.min.toFixed(2) + ' dBm</b></span><span>Tertinggi <b>' + st.max.toFixed(2) + ' dBm</b></span><span>Rata-rata <b>' + st.avg.toFixed(2) + ' dBm</b></span><span>' + st.n + ' titik</span>'
                    : '';
                el.hidden = pts.length > 0;
                el.textContent = pts.length ? '' : 'Belum ada history pada rentang ini. Redaman dicatat otomatis tiap 15 menit setelah add-on dipasang.';
                var labels = pts.map(function (p) { return fmt(p.t, r !== '1d'); });
                var data = pts.map(function (p) { return p.rx; });
                var line = function (v, c) { return {data: pts.map(function () { return v; }), borderColor: c, borderDash: [5, 4], borderWidth: 1, pointRadius: 0, fill: false}; };
                var ds = [
                    {label: 'Redaman (dBm)', data: data, borderColor: '#0ea5e9', backgroundColor: 'rgba(14,165,233,.12)', fill: true, tension: .25, pointRadius: pts.length > 80 ? 0 : 2, borderWidth: 2},
                    line(GOOD, 'rgba(5,150,105,.7)'), line(FAIR, 'rgba(220,38,38,.7)')
                ];
                if (chart) chart.destroy();
                chart = new Chart(document.getElementById('rxChart'), {type: 'line', data: {labels: labels, datasets: ds},
                    options: {responsive: true, maintainAspectRatio: false, animation: false, interaction: {mode: 'index', intersect: false},
                        plugins: {legend: {display: false}, tooltip: {filter: function (i) { return i.datasetIndex === 0; }, callbacks: {label: function (c) { return ' ' + c.parsed.y.toFixed(2) + ' dBm'; }}}},
                        scales: {x: {ticks: {maxTicksLimit: 8, maxRotation: 0}}, y: {suggestedMin: Math.min(FAIR - 3, (res.stats && res.stats.min) || FAIR), suggestedMax: Math.max(GOOD + 3, (res.stats && res.stats.max) || GOOD), title: {display: true, text: 'dBm'}}}}});
            });
        }
        document.querySelectorAll('#rxRange button').forEach(function (b) { b.onclick = function () { load(b.dataset.r); }; });
        load('7d');
    });
    </script>

    <div class="sec3">
        <?php foreach ($sec as $s): ?>
            <div class="card">
                <?= card_head($s[0], $s[1]) ?>
                <dl class="kvs">
                    <?php foreach ($s[2] as $k => $v):
                        $txt = is_array($v) ? '' : (string) $v;
                        $canCopy = !is_array($v) && in_array($k, $kvCopy, true) && $txt !== '' && $txt !== '-'; ?>
                        <div>
                            <div class="kv-t">
                                <dt><?= h($k) ?></dt>
                                <dd<?= in_array($k, $kvMono, true) ? ' class="mono"' : '' ?>><?= is_array($v) ? $v[0] : h($v) ?></dd>
                            </div>
                            <?php if ($canCopy): ?><button type="button" class="cp" title="Salin <?= h($k) ?>" data-c="<?= h($txt) ?>"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button><?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </dl>
            </div>
        <?php endforeach; ?>
    </div>
    <script>
    document.querySelectorAll('.kvs .cp').forEach(function (b) {
        b.addEventListener('click', function () {
            var t = b.getAttribute('data-c');
            function done() { b.classList.add('ok'); toast('Disalin: ' + t, true); setTimeout(function () { b.classList.remove('ok'); }, 1200); }
            if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).then(done); return; }
            var a = document.createElement('textarea'); a.value = t; a.style.position = 'fixed'; a.style.opacity = '0';
            document.body.appendChild(a); a.select(); try { document.execCommand('copy'); done(); } catch (e) {} document.body.removeChild(a);
        });
    });
    </script>

    <div class="grid2">
        <div class="card">
            <?= card_head('wifi', 'Ubah WiFi') ?>
            <div class="card-b form">
                <label>WLAN
                    <select id="wIdx">
                        <?php foreach ($wlans as $w): ?><option value="<?= h($w['idx']) ?>"><?= h($w['idx'] . ' — ' . $w['ssid'] . ' (' . ($w['band'] === '5' ? '5 GHz' : '2.4 GHz') . ')' . (wlan_off($w['enable']) ? ' (mati)' : '')) ?></option><?php endforeach; ?>
                        <?php if (!$wlans): ?><option value="1">1</option><?php endif; ?>
                    </select>
                </label>
                <label>SSID baru <input id="wSsid" maxlength="32" placeholder="Kosongkan jika tidak diubah"></label>
                <label>Password baru <input id="wPass" maxlength="63" placeholder="8–63 karakter, kosongkan jika tidak diubah"></label>
                <button class="btn primary" onclick="act('wifi',{id:DEV,index:wIdx.value,ssid:wSsid.value,pass:wPass.value},true)"><?= icon('save') ?>Simpan WiFi</button>
            </div>
        </div>
        <div class="card">
            <?= card_head('tag', 'Identitas Pelanggan') ?>
            <div class="card-b form">
                <label>Router
                    <input value="<?= h($d['group'] !== '' ? $d['group'] : ($PRl ? 'Tidak cocok dengan router panel' : '-')) ?>" disabled></label>
                <label>Area / kelompok <span class="muted small">(tag 1, opsional — mis. ODP atau dusun)</span>
                    <input id="tArea" value="<?= h($d['area']) ?>" placeholder="mis. ODP-03"></label>
                <label>Nama pelanggan <span class="muted small">(tag 2)</span>
                    <input id="tName" value="<?= h($d['name']) ?>" placeholder="mis. Budi Santoso"></label>
                <button class="btn primary" onclick="act('tags_set',{id:DEV,area:tArea.value,name:tName.value},true)"><?= icon('save') ?>Simpan Identitas</button>
                <?php if ($d['tags_rest']): ?>
                <div class="extra-tags"><span class="muted small">Tag lain:</span>
                    <?php foreach ($d['tags_rest'] as $t): ?>
                        <span class="tag big"><?= h($t) ?> <a href="#" onclick="act('tag_del',{id:DEV,tag:<?= h(json_encode($t)) ?>},true);return false">×</a></span>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="card">
        <?= card_head('server', 'Koneksi WAN', '<span class="chip">' . nf(count($wans)) . '</span>') ?>
        <div class="scroll">
        <table class="tbl">
            <thead><tr><th>Nama</th><th>Tipe</th><th>Mode</th><th>VLAN</th><th>IP</th><th>Status</th><th>Uptime</th></tr></thead>
            <tbody>
            <?php foreach ($wans as $x):
                $wen = $x['enable'] === null ? null : !wlan_off($x['enable']); ?>
                <tr>
                    <td class="mono nowrap"><?= h($x['name']) ?><?php if ($x['user'] !== ''): ?><span class="info-i" tabindex="0" aria-label="User PPPoE: <?= h($x['user']) ?>" data-tip="User PPPoE: <?= h($x['user']) ?>">i</span><?php endif; ?></td>
                    <td><?= h($x['proto']) ?></td>
                    <td class="nowrap"><span class="badge <?= $x['mode'] === 'Bridge' ? 'fair' : ($x['mode'] === 'Route' ? 'good' : 'na') ?>"><?= h($x['mode']) ?></span></td>
                    <td><?= h($x['vlan']) ?></td>
                    <td class="mono"><?= h($x['ip']) ?></td>
                    <td class="nowrap"><?php
                        if ($x['status'] !== '') {
                            echo strcasecmp($x['status'], 'Connected') === 0 ? '<span class="st on"><i></i>Connected</span>' : '<span class="st off"><i></i>' . h($x['status']) . '</span>';
                        } elseif ($wen === null) {
                            echo '-';
                        } else {
                            echo $wen ? '<span class="st on"><i></i>Aktif</span>' : '<span class="st off"><i></i>Mati</span>';
                        }
                    ?></td>
                    <td class="nowrap"><?= ($x['uptime'] !== null && $x['uptime'] !== '') ? h(fmt_uptime($x['uptime'])) : '-' ?></td>
                </tr>
            <?php endforeach; if (!$wans): ?><tr><td colspan="7" class="empty">Data WAN belum tersedia — klik Refresh</td></tr><?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>

    <?php
    $offN = 0;
    foreach ($wlans as $w) {
        if (wlan_off($w['enable'])) {
            $offN++;
        }
    }
    $wbtn = $offN ? '<button class="btn sm" id="ssidBtn" onclick="toggleSsid()">' . icon('wifi') . '<span>Lihat semua SSID (' . $offN . ' mati)</span></button>' : '';
    ?>
    <div class="card">
        <?= card_head('wifi', 'Jaringan WiFi', '<span class="chip">' . nf(count($wlans) - $offN) . ' aktif</span>' . $wbtn) ?>
        <div class="scroll">
        <table class="tbl" id="ssidTable">
            <thead><tr><th>#</th><th>SSID</th><th>Band</th><th>Status</th><th>Channel</th><th>Keamanan</th><th>SSID Tersembunyi</th><th class="r">Daya Pancar</th><th class="r">Klien</th></tr></thead>
            <tbody>
            <?php foreach ($wlans as $w): $off = wlan_off($w['enable']); ?>
                <tr<?= $off ? ' class="ssid-off"' : '' ?>><td><?= h($w['idx']) ?></td><td><?= h($w['ssid']) ?></td>
                    <td><span class="band <?= $w['band'] === '5' ? 'b5' : 'b24' ?>"><?= $w['band'] === '5' ? '5 GHz' : '2.4 GHz' ?></span></td>
                    <td><?= $w['enable'] === null ? '-' : ($off ? '<span class="st off"><i></i>Mati</span>' : '<span class="st on"><i></i>Aktif</span>') ?></td>
                    <td><?= h((string) $w['channel'] === '0' ? 'Auto' : $w['channel']) ?></td>
                    <td><?= h($w['sec']) ?></td>
                    <td><?= $w['hidden'] === null ? '-' : ($w['hidden'] ? 'Ya' : 'Tidak') ?></td>
                    <td class="r"><?= h($w['power']) ?></td>
                    <td class="r"><?= h($w['clients']) ?></td></tr>
            <?php endforeach; if (!$wlans): ?><tr><td colspan="9" class="empty">Data WLAN belum tersedia — klik Refresh</td></tr><?php elseif ($offN === count($wlans)): ?><tr class="no-active"><td colspan="9" class="empty">Tidak ada SSID aktif</td></tr><?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>

    <div class="card">
        <?= card_head('users', 'Perangkat Terhubung', '<span class="chip">' . nf(count($hosts)) . '</span>') ?>
        <div class="scroll">
        <table class="tbl">
            <thead><tr><th>Hostname</th><th>IP</th><th>MAC</th><th>Interface</th><th>Status</th></tr></thead>
            <tbody>
            <?php foreach ($hosts as $hst): ?>
                <tr><td><?= h($hst['name']) ?></td><td class="mono"><?= h($hst['ip']) ?></td><td class="mono"><?= h($hst['mac']) ?></td>
                    <td><?= h($hst['iface']) ?></td>
                    <td><?= $hst['active'] === null ? '-' : ($hst['active'] ? '<span class="st on"><i></i>Aktif</span>' : '<span class="st off"><i></i>Tidak aktif</span>') ?></td></tr>
            <?php endforeach; if (!$hosts): ?><tr><td colspan="5" class="empty">Data host belum tersedia — klik Refresh</td></tr><?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
    <script>
    var DEV = <?= json_encode($d['id']) ?>;
    function toggleSsid() {
        var t = document.getElementById('ssidTable'), b = document.getElementById('ssidBtn');
        var all = t.classList.toggle('all');
        b.querySelector('span').textContent = all ? 'Sembunyikan SSID mati' : 'Lihat semua SSID (<?= (int) $offN ?> mati)';
    }
    </script>
    <?php
}

function page_faults($S, $acs)
{
    $faults = $acs->faults();
    if ($acs->lastError) {
        echo '<div class="alert err">' . h($acs->lastError) . '</div>';
    }
    usort($faults, function ($a, $b) {
        return strcmp(isset($b['timestamp']) ? $b['timestamp'] : '', isset($a['timestamp']) ? $a['timestamp'] : '');
    });
    $extra = '<span class="chip">' . nf(count($faults)) . '</span>';
    if ($faults) {
        $extra .= '<button class="btn danger sm" onclick="if(confirm(\'Hapus semua fault?\'))act(\'fault_del_all\',{},true)">' . icon('trash') . 'Hapus Semua</button>';
    }
    ?>
    <div class="card">
        <?= card_head('alert', 'Faults', $extra) ?>
        <div class="scroll">
        <table class="tbl">
            <thead><tr><th>Perangkat</th><th>Channel</th><th>Kode</th><th>Pesan</th><th class="r">Retry</th><th>Waktu</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($faults as $f):
                $ts = acs_ts(isset($f['timestamp']) ? $f['timestamp'] : null); ?>
                <tr>
                    <td class="mono"><?= dev_link($f['device'], $f['device']) ?></td>
                    <td><?= h(isset($f['channel']) ? $f['channel'] : '-') ?></td>
                    <td><span class="badge poor"><?= h(isset($f['code']) ? $f['code'] : '-') ?></span></td>
                    <td class="wrap"><?= h(isset($f['message']) ? $f['message'] : '-') ?></td>
                    <td class="r"><?= (int) (isset($f['retries']) ? $f['retries'] : 0) ?></td>
                    <td class="mono nowrap"><?= $ts ? date('Y-m-d H:i', $ts) : '-' ?></td>
                    <td><button class="btn sm" onclick="act('fault_del',{id:<?= h(json_encode($f['_id'])) ?>},true)"><?= icon('trash') ?>Hapus</button></td>
                </tr>
            <?php endforeach; if (!$faults): ?>
                <tr><td colspan="7" class="empty">Tidak ada fault — semua perangkat sehat</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php
}

function page_mapping($S, $devs)
{
    $loc = locations_all();
    $list = [];
    foreach ($devs as $d) {
        $list[] = [
            'id' => $d['id'], 'serial' => $d['serial'], 'pc' => $d['pc'], 'pppoe' => $d['pppoe'], 'name' => $d['name'], 'group' => $d['group'],
            'online' => $d['online'], 'rx' => $d['rx'], 'rxc' => $d['rxc'],
            'lat' => isset($loc[$d['id']]) ? $loc[$d['id']]['lat'] : null,
            'lng' => isset($loc[$d['id']]) ? $loc[$d['id']]['lng'] : null,
        ];
    }
    ?>
    <link rel="stylesheet" href="assets/leaflet/leaflet.css">
    <div class="card">
        <?= card_head('map', 'Mapping Perangkat') ?>
        <div class="filters">
            <select id="mDev" style="flex:2">
                <option value="">— Pilih perangkat untuk diset lokasinya —</option>
                <?php foreach ($list as $x): ?>
                    <option value="<?= h($x['id']) ?>"><?= h(($x['name'] ? $x['name'] . ' · ' : '') . $x['serial'] . ' · ' . $x['pc'] . ($x['group'] ? ' · ' . $x['group'] : '') . ($x['lat'] === null ? '' : ' 📍')) ?></option>
                <?php endforeach; ?>
            </select>
            <button class="btn" onclick="myLoc()"><?= icon('locate') ?>Lokasi saya</button>
            <button class="btn danger" onclick="delLoc()"><?= icon('trash') ?>Hapus lokasi</button>
        </div>
        <p class="muted small" style="padding:0 20px 12px;margin:0">Pilih perangkat, lalu klik di peta untuk menyimpan lokasinya. Marker hijau = online, merah = offline.</p>
        <div id="map"></div>
    </div>
    <script src="assets/leaflet/leaflet.js"></script>
    <script>
    var DEVS = <?= json_encode($list) ?>, markers = {};
    var map = L.map('map').setView([-2.5, 118], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 20, attribution: '&copy; OpenStreetMap'}).addTo(map);
    function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
    function icon(d){
        var c = d.online ? '#059669' : '#dc2626';
        return L.divIcon({className:'', iconSize:[18,18], html:'<div style="width:18px;height:18px;border-radius:50%;background:'+c+';border:3px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.4)"></div>'});
    }
    function draw(d){
        if (markers[d.id]) { map.removeLayer(markers[d.id]); delete markers[d.id]; }
        if (d.lat === null) return;
        markers[d.id] = L.marker([d.lat, d.lng], {icon: icon(d)}).addTo(map).bindPopup(
            '<b>'+esc(d.name||d.pc)+'</b><br>'+esc(d.pc)+' · SN: '+esc(d.serial)+'<br>Nama: '+esc(d.name||'-')+'<br>Profile: '+esc(d.group||'-')+
            '<br>Status: '+(d.online?'Online':'Offline')+'<br>RX: '+(d.rx===null?'N/A':d.rx+' dBm')+
            '<br><a href="?page=device&id='+encodeURIComponent(d.id)+'">Detail →</a>');
    }
    DEVS.forEach(draw);
    var pts = DEVS.filter(function(d){return d.lat!==null;}).map(function(d){return [d.lat,d.lng];});
    if (pts.length) map.fitBounds(pts, {padding:[40,40], maxZoom:17});
    function sel(){ var id = document.getElementById('mDev').value; return DEVS.find(function(d){return d.id===id;}); }
    map.on('click', function(e){
        var d = sel();
        if (!d) { toast('Pilih perangkat dulu', false); return; }
        api('location_save', {id:d.id, lat:e.latlng.lat, lng:e.latlng.lng}).then(function(r){
            toast(r.msg, r.ok);
            if (r.ok) { d.lat = +e.latlng.lat.toFixed(6); d.lng = +e.latlng.lng.toFixed(6); draw(d); markers[d.id].openPopup(); }
        });
    });
    document.getElementById('mDev').addEventListener('change', function(){
        var d = sel(); if (d && d.lat !== null) { map.setView([d.lat,d.lng], 17); markers[d.id].openPopup(); }
    });
    function delLoc(){
        var d = sel(); if (!d) { toast('Pilih perangkat dulu', false); return; }
        api('location_del', {id:d.id}).then(function(r){ toast(r.msg, r.ok); d.lat = d.lng = null; draw(d); });
    }
    function myLoc(){
        if (!navigator.geolocation) return toast('Browser tidak mendukung lokasi', false);
        navigator.geolocation.getCurrentPosition(function(p){ map.setView([p.coords.latitude,p.coords.longitude], 18); },
            function(){ toast('Izin lokasi ditolak', false); });
    }
    </script>
    <?php
}

/** Alamat web ONT: IP TR-069 (IP virtual bila lewat panel utama). */
function ip_target($ip, $group = '', $G = [])
{
    $ip = trim((string) $ip);
    if ($ip === '') {
        return null;
    }
    return ['host' => $ip, 'url' => 'http://' . $ip, 'mapped' => false];
}

/** Link IP yang bisa diklik (buka web ONT di tab baru; perlu tersambung ke jaringan VPN). */
function ip_link($ip, $group = '', $G = [])
{
    $t = ip_target($ip);
    if (!$t) {
        return '-';
    }
    return '<a class="iplink" href="' . h($t['url']) . '" target="_blank" rel="noopener" title="Buka ' . h($t['url']) . ' (perlu tersambung ke jaringan VPN/ZeroTier panel)">' . cut15($ip) . '</a>';
}

/** Lencana perubahan redaman 24 jam. */
function delta_badge($v, $S)
{
    if ($v === null) {
        return '<span class="muted">–</span>';
    }
    $drop = (float) (isset($S['rx_drop_db']) ? $S['rx_drop_db'] : 2);
    $cls = $v <= -$drop ? 'poor' : ($v < 0 ? 'fair' : 'good');
    $txt = ($v > 0 ? '+' : '') . number_format($v, 1, ',', '');
    return '<span class="badge ' . $cls . '" title="Perubahan redaman dibanding 24 jam lalu">' . ($v <= -$drop ? '▼ ' : '') . $txt . ' dB</span>';
}

function page_settings($S)
{
    $tzs = ['Asia/Jakarta', 'Asia/Makassar', 'Asia/Jayapura'];
    ?>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <div class="grid2">
            <div class="card">
                <?= card_head('server', 'Koneksi GenieACS') ?>
                <div class="card-b form">
                    <label>Nama Panel <input name="app_name" value="<?= h($S['app_name']) ?>"></label>
                    <label>URL NBI GenieACS <input id="sUrl" name="acs_url" value="<?= h($S['acs_url']) ?>" placeholder="http://127.0.0.1:7557"></label>
                    <p class="muted small" style="margin:-6px 0 4px">Di VPS yang sama cukup <code>http://127.0.0.1:7557</code>. Jangan membuka port 7557 ke internet: NBI tidak punya login.</p>
                    <div class="row">
                        <label>NBI Username <input id="sUser" name="acs_user" value="<?= h($S['acs_user']) ?>" autocomplete="off"></label>
                        <label>NBI Password <input id="sPass" type="password" name="acs_pass" placeholder="<?= $S['acs_pass'] !== '' ? '•••••• (tersimpan)' : 'kosong' ?>" autocomplete="new-password"></label>
                    </div>
                    <label class="chk"><input id="sClear" type="checkbox" name="acs_pass_clear" value="1"> Hapus password NBI tersimpan</label>
                    <div class="btns">
                        <button type="button" class="btn" onclick="act('test',{url:sUrl.value,user:sUser.value,pass:sPass.value,clear:sClear.checked})"><?= icon('plug') ?>Tes Koneksi</button>
                        <button class="btn primary"><?= icon('save') ?>Simpan</button>
                    </div>
                </div>
            </div>
            <div class="card">
                <?= card_head('activity', 'Monitoring') ?>
                <div class="card-b form">
                    <label class="chk"><input type="checkbox" name="online_auto" value="1" <?= (!isset($S['online_auto']) || $S['online_auto']) ? 'checked' : '' ?>> Tentukan status offline otomatis dari interval laporan ONT</label>
                    <label>Batas offline manual (menit) <input type="number" min="1" name="online_minutes" value="<?= (int) $S['online_minutes'] ?>"></label>
                    <label>Zona Waktu
                        <select name="timezone"><?php foreach ($tzs as $tz): ?><option <?= $S['timezone'] === $tz ? 'selected' : '' ?>><?= $tz ?></option><?php endforeach; ?></select>
                    </label>
                    <div class="row">
                        <label>RX Excellent jika ≥ (dBm) <input type="number" step="0.1" name="rx_good" value="<?= h($S['rx_good']) ?>"></label>
                        <label>RX Fair jika ≥ (dBm) <input type="number" step="0.1" name="rx_fair" value="<?= h($S['rx_fair']) ?>"></label>
                    </div>
                </div>
            </div>
        </div>
        <?php $rs = rx_status(); $PRs = panel_routers(); global $acs; $provOn = $acs->exists('provisions', RX_PROVISION); ?>
        <div class="grid2">
            <div class="card">
                <?= card_head('activity', 'History Redaman') ?>
                <div class="card-b form">
                    <div class="row">
                        <label>Simpan history (hari) <input type="number" min="14" max="730" name="rx_keep_days" value="<?= (int) $S['rx_keep_days'] ?>"></label>
                        <label>Tandai memburuk jika turun ≥ (dB/24 jam) <input type="number" step="0.5" min="0.5" max="20" name="rx_drop_db" value="<?= h($S['rx_drop_db']) ?>"></label>
                    </div>
                    <dl class="kvl">
                        <div><dt>Pencatatan terakhir</dt><dd><?= $rs['last'] ? h(date('d M Y H:i', $rs['last']['at'])) . ' · ' . nf($rs['last']['saved']) . ' titik baru' : '<span class="muted">belum pernah</span>' ?></dd></div>
                        <div><dt>ONT tercatat</dt><dd><?= nf($rs['devs']) ?></dd></div>
                        <div><dt>Data sejak</dt><dd><?= $rs['since'] ? h(date('d M Y', $rs['since'])) : '-' ?></dd></div>
                        <div><dt>Ukuran database</dt><dd><?= number_format($rs['size'] / 1048576, 1, ',', '.') ?> MB</dd></div>
                        <div><dt>Baca ulang RX tiap Inform</dt><dd><?= $provOn ? '<span class="badge good">Aktif</span>' : '<span class="badge fair">Belum</span>' ?></dd></div>
                    </dl>
                    <p class="muted small" style="margin:0">Redaman dicatat otomatis tiap 15 menit. Parameter bawaan biasanya hanya membaca RX sekali sehari, sehingga grafik jarang berubah. Pasang provision tambahan <code><?= RX_PROVISION ?></code> agar RX dibaca ulang setiap Inform (provision lain tidak diubah).</p>
                    <div class="btns">
                        <?php if ($provOn): ?>
                            <button type="button" class="btn" onclick="if(confirm('Hapus provision RX? RX kembali dibaca sesuai provision bawaan.'))act('rx_prov_remove',{},true)"><?= icon('trash') ?>Hapus provision RX</button>
                        <?php else: ?>
                            <button type="button" class="btn primary" onclick="if(confirm('Pasang provision RX di GenieACS? RX semua ONT akan dibaca ulang setiap Inform berkala.'))act('rx_prov_install',{},true)"><?= icon('plug') ?>Pasang provision RX</button>
                        <?php endif; ?>
                        <button type="button" class="btn" onclick="act('rx_collect',{},true)"><?= icon('refresh') ?>Catat sekarang</button>
                    </div>
                </div>
            </div>
            <div class="card">
                <?= card_head('layers', 'Panel Utama') ?>
                <div class="card-b">
                    <?php if (!$PRs['linked']): ?>
                        <p class="muted small" style="margin:0">Panel ACS dipasang mandiri (tidak lewat menu Add-on panel utama). ONT dikelompokkan memakai tag 1 (area).</p>
                    <?php else: ?>
                        <dl class="kvl">
                            <div><dt>Status</dt><dd><?= $PRs['ok'] ? '<span class="badge good">Terhubung</span>' : '<span class="badge poor">Gagal</span>' ?></dd></div>
                            <div><dt>Router</dt><dd><?= nf(count($PRs['routers'])) ?></dd></div>
                            <?php if (!empty($PRs['panel']['url'])): ?><div><dt>Alamat</dt><dd><a href="<?= h(rtrim($PRs['panel']['url'], '/')) ?>/" target="_blank" rel="noopener"><?= h($PRs['panel']['url']) ?></a></dd></div><?php endif; ?>
                        </dl>
                        <?php if ($PRs['error']): ?><div class="alert err" style="margin-top:10px"><?= h($PRs['error']) ?></div><?php endif; ?>
                        <p class="muted small" style="margin:10px 0 0">Router setiap ONT ditentukan dari IP virtual router di panel utama. Tambah atau ubah router di panel utama, Panel ACS ikut menyesuaikan.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <div class="card">
            <?= card_head('user', 'Akun Admin Panel') ?>
            <div class="card-b form">
                <div class="row">
                    <label>Username <input name="admin_user" value="<?= h($S['admin_user']) ?>"></label>
                    <label>Password baru <input type="password" name="admin_pass" placeholder="Kosongkan jika tidak diubah" autocomplete="new-password"></label>
                </div>
                <button class="btn primary"><?= icon('save') ?>Simpan Pengaturan</button>
            </div>
        </div>
    </form>
    <?php
}

/* =================================================================
 *  LAYOUT
 * ================================================================= */

function css()
{
    return <<<CSS
:root{--ink:#1e293b;--ink2:#475569;--muted:#64748b;--bg:#f8fafc;--panel:#fff;--line:#e2e8f0;--line2:#cbd5e1;--row:#f8fafc;
--side:#0f172a;--side2:#0b1220;--side-ink:#cbd5e1;--accent:#0369c7;--accent-h:#075ea8;--accent-soft:#e0f2fe;
--ok:#059669;--ok-bg:#d1fae5;--warn:#d97706;--warn-bg:#fef3c7;--bad:#dc2626;--bad-bg:#fee2e2;--vio:#7c3aed;--vio-bg:#ede9fe;
--r:16px;--h:40px;--shadow:0 1px 2px rgba(15,23,42,.05);
--font:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:ui-monospace,"Cascadia Mono",Consolas,"Liberation Mono",monospace}
:root[data-theme="dark"]{--ink:#f1f5f9;--ink2:#cbd5e1;--muted:#94a3b8;--bg:#020617;--panel:#0f172a;--line:#1e293b;--line2:#334155;--row:#131d33;
--side:#0b1120;--side2:#020617;--side-ink:#cfe3f0;--accent:#0ea5e9;--accent-h:#38bdf8;--accent-soft:rgba(14,165,233,.14);
--ok:#34d399;--ok-bg:rgba(16,185,129,.15);--warn:#fbbf24;--warn-bg:rgba(245,158,11,.15);--bad:#f87171;--bad-bg:rgba(239,68,68,.15);--vio:#a78bfa;--vio-bg:rgba(139,92,246,.15);
--shadow:0 1px 2px rgba(0,0,0,.4)}
*{box-sizing:border-box}
html,body{margin:0}
body{font-family:var(--font);background:var(--bg);color:var(--ink);font-size:14px;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{color:var(--accent-h)}
.i{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round;flex:none}
/* sidebar */
.side{position:fixed;top:0;left:0;bottom:0;width:256px;background:var(--side);color:var(--side-ink);z-index:70;display:flex;flex-direction:column;transition:transform .25s}
.brand{display:flex;align-items:center;gap:12px;padding:14px 20px;height:76px}
.logo{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#38bdf8,#2563eb);display:grid;place-items:center;color:#fff;box-shadow:0 6px 16px rgba(37,99,235,.35)}
.logo .i{width:22px;height:22px}
.brand b{display:block;color:#fff;font-size:17px;font-weight:800;letter-spacing:.4px}
.brand small{display:block;color:#38bdf8;font-size:10.5px;font-weight:600;letter-spacing:1.4px;margin-top:2px}
.side-chip{margin:4px 14px 16px;padding:11px 14px;border:1px solid rgba(148,163,184,.18);background:rgba(255,255,255,.03);border-radius:12px;display:flex;align-items:center;gap:9px;font-weight:700;font-size:13px;color:#fff;text-transform:uppercase;letter-spacing:.3px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(16,185,129,.18);flex:none}
.dot.bad{background:var(--bad);box-shadow:0 0 0 3px rgba(239,68,68,.18)}
.nav{flex:1;overflow-y:auto;padding:0 14px}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 13px;border-radius:12px;color:var(--side-ink);font-weight:500;font-size:14px;margin-bottom:4px}
.nav a:hover{background:rgba(255,255,255,.06);color:#fff}
.nav a.on{background:linear-gradient(90deg,#0284c7,#2563eb);color:#fff;font-weight:600;box-shadow:0 6px 16px rgba(37,99,235,.3)}
.side-user{display:flex;align-items:center;gap:11px;margin:12px 14px 14px;padding:10px 10px 10px 12px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid rgba(148,163,184,.14)}
.av{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#38bdf8,#2563eb);color:#fff;display:grid;place-items:center;font-weight:800;font-size:15px;flex:none}
.side-user div{flex:1;min-width:0}
.side-user b{display:block;color:#fff;font-size:13.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side-user small{display:block;color:#64748b;font-size:11px;margin-top:1px}
.side-out{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;color:var(--side-ink)}
.side-out:hover{background:rgba(239,68,68,.16);color:#f87171}
.shade{position:fixed;inset:0;background:rgba(2,6,23,.5);z-index:60;display:none}
/* topbar */
.wrap{margin-left:256px;min-height:100vh;display:flex;flex-direction:column}
.top{position:sticky;top:0;z-index:50;height:64px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:0 22px}
.top h1{margin:0;font-size:19px;font-weight:700;color:var(--ink)}
.top .sp{flex:1}
.ib{width:38px;height:38px;border-radius:10px;border:0;background:none;color:var(--ink2);display:grid;place-items:center;cursor:pointer}
.ib:hover{background:var(--row)}
.ib .i{width:20px;height:20px}
.pill{display:flex;align-items:center;gap:8px;height:38px;padding:0 14px;border:1px solid var(--line);border-radius:10px;font-weight:700;font-size:13px;color:var(--ink);text-transform:uppercase;letter-spacing:.3px;background:var(--panel)}
.who{display:flex;align-items:center;gap:6px;color:var(--ink2);font-weight:500}
.who .i{width:16px;height:16px}
.seg{display:inline-flex;gap:2px;padding:3px;border:1px solid var(--line);border-radius:10px;background:var(--bg)}
.seg button{border:0;background:transparent;padding:5px 10px;border-radius:7px;font:inherit;font-size:12px;font-weight:600;color:var(--muted);cursor:pointer}
.seg button.on{background:var(--panel);color:var(--ink);box-shadow:0 1px 2px rgba(0,0,0,.08)}
.rx-stats{display:flex;gap:18px;flex-wrap:wrap;padding:12px 20px 0;font-size:12.5px;color:var(--muted)}
.rx-stats b{color:var(--ink);font-weight:700}
.rx-wrap{position:relative;height:260px;padding:10px 16px 16px}
.rx-empty{position:absolute;inset:0;display:grid;place-items:center;text-align:center;padding:20px;font-size:13px}
.grp-pick{display:flex;align-items:center;gap:6px;height:38px;padding:0 4px 0 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--accent);cursor:pointer}
.grp-pick .i{width:16px;height:16px}
.dash-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.dash-ttl{font-size:13.5px;color:var(--muted)}
.dash-ttl b{color:var(--ink);font-weight:700}
.dash-head{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.dh-title{margin:0;font-size:22px;font-weight:800;letter-spacing:-.3px}
.dh-sub{color:var(--muted);font-size:13px;margin-top:4px}
.dh-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.dgrid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 18px}
.dgrid2{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:0 18px}
.blist{padding:6px 18px 14px}
.bl-row{padding:9px 0}
.bl-top{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:7px;font-size:13.5px}
.bl-name{display:flex;align-items:center;gap:8px;font-weight:600;min-width:0}
.bl-name i{width:9px;height:9px;border-radius:3px;flex:none}
.bl-name em{font-style:normal;font-weight:500;color:var(--muted);font-size:12px}
.bl-val{white-space:nowrap}.bl-val b{font-weight:700;margin-right:6px}.bl-val small{color:var(--muted);font-size:12px}
.bl-bar{height:6px;border-radius:999px;background:var(--line);overflow:hidden}
.bl-bar i{display:block;height:100%;border-radius:999px}
.bl-empty{padding:22px 0;text-align:center;color:var(--muted)}
dl.kvl{margin:0;padding:4px 18px 10px}
.kvl>div{display:flex;justify-content:space-between;align-items:baseline;gap:16px;padding:11px 0;border-bottom:1px dashed var(--line)}
.kvl>div:last-child{border-bottom:0}
.kvl dt{color:var(--muted);font-size:13px;white-space:nowrap}
.kvl dd{margin:0;font-weight:600;text-align:right;word-break:break-all;font-size:13.5px}
dl.kvs{margin:0;padding:2px 20px 8px}
.kvs>div{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 0;border-bottom:1px solid var(--line)}
.kvs>div:last-child{border-bottom:0}
.kv-t{min-width:0;flex:1}
.kvs dt{color:var(--muted);font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px}
.kvs dd{margin:0;font-weight:600;font-size:14.5px;color:var(--ink);word-break:break-all;line-height:1.4}
.kvs dd.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}
.cp{flex:none;width:32px;height:32px;display:grid;place-items:center;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer}
.cp svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.cp:hover{background:var(--accent-soft);color:var(--accent)}
.cp.ok{background:var(--ok-bg);color:var(--ok)}
.card-foot{padding:12px 18px;border-top:1px solid var(--line);text-align:right;font-size:13px;font-weight:600}
.dh-meta{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center;color:var(--muted);font-size:13px}
.tile.big.on{background:var(--ok-bg);color:var(--ok)}
.tile.big.off{background:var(--bad-bg);color:var(--bad)}
.dev-stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr))}
.ds{padding:14px 18px;border-right:1px solid var(--line);min-width:0}
.ds:last-child{border-right:0}
.ds>span{display:block;font-size:10.5px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
.ds>b{display:block;font-size:15px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ds>small{display:block;color:var(--muted);font-size:12px;margin-top:4px}
.ud{display:inline-block;font-weight:700;font-size:12.5px;white-space:nowrap}
.ud.up{color:var(--ok)}.ud.down{color:var(--bad)}
.sec3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 18px}
.grp-pick select{border:0;height:36px;padding:0 6px;width:auto;max-width:220px;background:transparent;color:var(--ink);font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:.3px;cursor:pointer}
.grp-pick select:focus{box-shadow:none}
.grp-pick select option{text-transform:none;font-weight:500}
.nm{color:var(--ink);font-weight:600;display:inline-flex;align-items:center}
.sn{color:var(--accent);font-weight:500}
.sn:hover{color:var(--accent-h);text-decoration:underline}
.info-i{position:relative;display:inline-grid;place-items:center;width:18px;height:18px;margin-left:8px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font:italic 700 11px/1 Georgia,serif;cursor:pointer;vertical-align:middle;outline:none}
.info-i:hover,.info-i:focus{background:var(--accent);color:#fff}
.band{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:700;white-space:nowrap}
.band.b24{background:var(--accent-soft);color:var(--accent)}
.band.b5{background:var(--vio-bg);color:var(--vio)}
.iplink{color:var(--accent)}
.iplink:hover{text-decoration:underline;color:var(--accent-h)}
.grid-g{display:grid;grid-template-columns:1fr;gap:0 18px;align-items:start}
@media(min-width:1440px){.grid-g{grid-template-columns:minmax(0,1.8fr) minmax(0,1fr)}}
.form .btns{justify-content:flex-end}
.form > .btn{display:flex;width:max-content;margin-left:auto}
.preview{background:var(--row);border:1px dashed var(--line2);border-radius:10px;padding:10px 12px;font-size:13px;margin-bottom:14px}
.band.mini{margin-left:6px;padding:1px 6px;font-size:10px;vertical-align:middle;cursor:help}
.info-i:hover::after,.info-i:focus::after{content:attr(data-tip);position:absolute;left:calc(100% + 8px);top:50%;transform:translateY(-50%);background:#0f172a;color:#fff;padding:6px 10px;border-radius:8px;font:500 12px/1.3 var(--font);white-space:nowrap;z-index:20;box-shadow:0 6px 16px rgba(0,0,0,.25)}
.nm.none{color:var(--muted);font-weight:500;font-style:italic}
a.nm:hover{color:var(--ink);text-decoration:underline}
a.nm.none:hover{color:var(--muted)}
.led{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:10px;flex:none}
.led.on{background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}
.led.off{background:var(--bad);box-shadow:0 0 0 3px var(--bad-bg)}
#ssidTable tr.ssid-off{display:none}
#ssidTable.all tr.ssid-off{display:table-row}
#ssidTable.all tr.no-active{display:none}
#ssidTable tr.ssid-off td{color:var(--muted)}
#tgMenu{display:none}
main{padding:22px;flex:1}
footer{padding:0 22px 20px;color:var(--muted);font-size:12px}
/* cards */
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);margin-bottom:18px;overflow:hidden}
.card-h{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.ti,.tile{width:36px;height:36px;border-radius:12px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;flex:none}
.tile{width:40px;height:40px}.tile.big{width:52px;height:52px;border-radius:14px}.tile.big .i{width:24px;height:24px}
.ct{font-size:18px;font-weight:700}
.sp{flex:1}
.card-b{padding:18px}
.chip{display:inline-flex;align-items:center;height:26px;padding:0 10px;border-radius:999px;background:var(--accent-soft);color:var(--accent);font-size:12px;font-weight:600}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 18px}
/* info row */
.info-row{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-bottom:18px}
.info-row .card{margin-bottom:0}
.card.info{display:flex;align-items:center;gap:16px;padding:16px 18px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;align-items:center;flex:1;min-width:0}
.kv>span{font-size:10.5px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.kv>b{font-size:14.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mono-s{font-family:var(--mono);font-size:13px!important}
.bar{position:relative;height:14px;border-radius:999px;background:var(--line);overflow:hidden}
.bar i{position:absolute;left:0;top:0;bottom:0;border-radius:999px;background:var(--ok)}.bar i.bad{background:var(--bad)}
.bar em{position:relative;display:block;text-align:center;font-style:normal;font-size:10px;font-weight:600;line-height:14px;color:var(--ink)}
/* kpi */
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:18px}
.kpi{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);padding:16px 18px 15px;color:var(--ink);display:flex;flex-direction:column;gap:10px;transition:border-color .15s,transform .15s,box-shadow .15s;overflow:hidden}
.kpi:hover{color:var(--ink);border-color:var(--line2);transform:translateY(-2px);box-shadow:0 8px 20px rgba(15,23,42,.08)}
.k-head{display:flex;align-items:center;gap:10px}
.k-ico{width:36px;height:36px;border-radius:11px;display:grid;place-items:center;flex:none}
.k-ico.blue{background:var(--accent-soft);color:var(--accent)}.k-ico.green{background:var(--ok-bg);color:var(--ok)}
.k-ico.red{background:var(--bad-bg);color:var(--bad)}.k-ico.amber{background:var(--warn-bg);color:var(--warn)}
.k-lbl{font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--muted);flex:1}
.k-pct{font-size:12px;font-weight:700;padding:3px 8px;border-radius:999px}
.k-pct.ok{background:var(--ok-bg);color:var(--ok)}.k-pct.bad{background:var(--bad-bg);color:var(--bad)}
.k-val{font-size:32px;font-weight:800;letter-spacing:-.8px;line-height:1}
.k-val small{font-size:14px;font-weight:600;color:var(--muted);letter-spacing:0;margin-left:2px}
.k-meter{display:flex;height:7px;border-radius:999px;background:var(--line);overflow:hidden}
.k-meter i{display:block;height:100%}
.k-meter:not(.seg) i{border-radius:999px}
.k-meter i.blue{background:var(--accent)}.k-meter i.ok{background:var(--ok)}.k-meter i.warn{background:var(--warn)}.k-meter i.bad{background:var(--bad)}
.k-sub{display:flex;justify-content:space-between;gap:8px;font-size:12px;color:var(--muted)}
.k-sub.legend{flex-wrap:wrap;justify-content:flex-start;gap:4px 12px}
.k-sub.legend span{display:inline-flex;align-items:center;gap:5px}
.k-sub.legend i{width:8px;height:8px;border-radius:2px}
.k-sub.legend i.ok{background:var(--ok)}.k-sub.legend i.warn{background:var(--warn)}.k-sub.legend i.bad{background:var(--bad)}.k-sub.legend i.na{background:var(--line2)}
.k-sub.legend b{color:var(--ink);font-weight:700}
/* stats */
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr)) minmax(0,1.9fr);gap:14px;margin-bottom:18px}
.info-row+.stats{margin-top:0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);padding:14px 16px;color:var(--ink);display:block;transition:border-color .15s,transform .15s}
.stat:hover{border-color:var(--line2);color:var(--ink);transform:translateY(-1px)}
.st-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px}
.st-lbl{font-size:10.5px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);padding-top:4px}
.st-ico{width:34px;height:34px;border-radius:10px;display:grid;place-items:center}
.st-ico.blue{background:var(--accent-soft);color:var(--accent)}.st-ico.green{background:var(--ok-bg);color:var(--ok)}
.st-ico.amber{background:var(--warn-bg);color:var(--warn)}.st-ico.red{background:var(--bad-bg);color:var(--bad)}
.st-row{display:flex;justify-content:space-between;align-items:baseline;color:var(--ink2);font-size:13px;margin-top:2px}
.st-row b{color:var(--ink);font-size:14px;font-weight:700}
.st-row b.big{font-size:24px;font-weight:800;letter-spacing:-.3px}
.stat.wide{display:flex;gap:16px;align-items:center}
.wide-body{flex:1;min-width:0}
.wr{display:flex;justify-content:space-between;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:var(--ink2);padding:2px 0}
.wr em{font-style:normal;color:var(--muted);font-weight:600}
.wr b{font-size:14px;text-transform:none}
.c-ok{color:var(--ok)}.c-warn{color:var(--warn)}.c-bad{color:var(--bad)}
.foot{font-size:11.5px;color:var(--muted);margin-top:4px}
/* tables */
.scroll{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{background:var(--row);color:var(--muted);font-size:10.5px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;text-align:left;padding:11px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
.tbl td{padding:11px 16px;border-bottom:1px solid var(--line);vertical-align:middle;font-size:13.5px}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl tbody tr:hover td{background:var(--row)}
.r{text-align:right}.nowrap{white-space:nowrap}.wrap{min-width:220px}
.mono{font-family:var(--mono);font-size:12.5px}
.empty{text-align:center;color:var(--muted);padding:26px!important}
.muted{color:var(--muted)}.small{font-size:12.5px}
.st{display:inline-flex;align-items:center;gap:6px;font-weight:600;font-size:12.5px}
.st i{width:8px;height:8px;border-radius:50%}
.st.on{color:var(--ok)}.st.on i{background:var(--ok)}.st.off{color:var(--bad)}.st.off i{background:var(--bad)}
.badge{display:inline-flex;align-items:center;height:24px;padding:0 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.good{background:var(--ok-bg);color:var(--ok)}.badge.fair{background:var(--warn-bg);color:var(--warn)}
.badge.poor{background:var(--bad-bg);color:var(--bad)}.badge.na{background:var(--row);color:var(--muted);border:1px solid var(--line)}
.tag{display:inline-block;background:var(--accent-soft);color:var(--accent);border-radius:6px;padding:1px 7px;font-size:11px;font-family:var(--font);margin-left:6px;font-weight:600}
.tag.big{font-size:13px;padding:5px 10px;margin:0 6px 8px 0}.tag a{color:var(--bad);margin-left:4px;font-weight:800}
.tag.g{margin-left:0;font-size:11.5px;padding:2px 8px}
.extra-tags{margin:14px 0 4px}
.chart{position:relative;height:290px}
/* forms */
.filters{display:flex;flex-wrap:wrap;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
input,select{font:inherit;height:var(--h);padding:0 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--ink);width:100%}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.filters input,.filters select{flex:1;min-width:160px;width:auto}
.form label{display:block;font-size:12px;font-weight:600;color:var(--ink2);margin-bottom:14px;flex:1;min-width:180px}
.form label input,.form label select{margin-top:6px;display:block;width:100%}
.form .chk{display:flex;gap:8px;align-items:center;font-weight:500}.form .chk input{width:16px;height:16px;margin:0}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.row input{flex:1;width:auto}
.btn{display:inline-flex;align-items:center;gap:7px;height:var(--h);padding:0 15px;font:inherit;font-weight:600;font-size:13.5px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:10px;cursor:pointer;white-space:nowrap}
.btn .i{width:16px;height:16px}
.btn:hover{background:var(--row);color:var(--ink)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn.primary:hover{background:var(--accent-h)}
.btn.danger{color:var(--bad)}.btn.danger:hover{background:var(--bad-bg)}
.btn.sm{height:32px;padding:0 11px;font-size:12.5px}
.btn:disabled{opacity:.6;cursor:wait}
/* device */
.dev-head{display:flex;justify-content:space-between;flex-wrap:wrap;gap:14px;padding:18px;border-bottom:1px solid var(--line)}
.dh-left{display:flex;gap:14px;align-items:center}
.back{display:inline-flex;align-items:center;gap:2px;font-size:12.5px;font-weight:600}.back .i{width:15px;height:15px}
.dev-head h2{margin:3px 0 7px;font-size:20px;font-weight:700}
.dh-badges{display:flex;gap:10px;align-items:center}
.btns{display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap}
.info-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:16px 20px;padding:18px}
.info-grid .lbl{font-size:10.5px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.info-grid .v{font-weight:600;margin-top:4px;word-break:break-all}
/* misc */
.alert{padding:12px 16px;border-radius:12px;margin-bottom:18px;font-size:13.5px;font-weight:500}
.alert.err{background:var(--bad-bg);color:var(--bad)}.alert.ok{background:var(--ok-bg);color:var(--ok)}
.alert a{color:inherit;text-decoration:underline}
#map{height:66vh;min-height:380px}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#0f172a;color:#fff;padding:12px 18px;border-radius:12px;font-size:13.5px;font-weight:500;z-index:999;max-width:90%;box-shadow:0 10px 30px rgba(0,0,0,.25)}
.toast.err{background:#b91c1c}
@media(max-width:1199px){.dgrid3,.sec3{grid-template-columns:1fr 1fr}.dev-stats{grid-template-columns:repeat(3,minmax(0,1fr))}.ds{border-bottom:1px solid var(--line)}.ds:nth-child(3n){border-right:0}}
@media(max-width:1199px){.stats{grid-template-columns:repeat(4,minmax(0,1fr))}.stat.wide{grid-column:1/-1}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:1023px){.dgrid3,.dgrid2,.sec3{grid-template-columns:1fr}}
@media(max-width:1023px){
 .side{transform:translateX(-100%)}.side.open{transform:none}.shade.open{display:block}
 .wrap{margin-left:0}#tgMenu{display:grid}
 .info-row{grid-template-columns:1fr}.grid2{grid-template-columns:1fr}
 .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
 .who span,.pill span.lbl{display:none}
 .grp-pick select{max-width:130px}
 .grid-g{grid-template-columns:1fr}
}
@media(max-width:560px){.dev-stats{grid-template-columns:1fr 1fr}.ds:nth-child(3n){border-right:1px solid var(--line)}.ds:nth-child(2n){border-right:0}}
@media(max-width:560px){.grp-pick .i{display:none}.grp-pick{padding-left:4px}.grp-pick select{max-width:110px}.kpis{grid-template-columns:1fr}.k-val{font-size:28px}main{padding:14px}.top{padding:0 12px;gap:8px}.top h1{font-size:17px}.pill{padding:0 10px}}
CSS;
}

function theme_boot()
{
    return "<script>try{var t=localStorage.getItem('acs-theme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>";
}

function layout_start($S, $page, $title, $error, $flash)
{
    $nav = [
        'dashboard' => ['Dashboard', 'grid'], 'devices' => ['ONT Devices', 'router'], 'faults' => ['Faults', 'alert'],
        'mapping' => ['Mapping', 'map'], 'settings' => ['Settings', 'settings'],
    ];
    $cur = $page === 'device' ? 'devices' : $page;
    $host = parse_url($S['acs_url'], PHP_URL_HOST) ?: 'GenieACS';
    if (in_array($host, ['127.0.0.1', 'localhost'], true)) {
        $host = 'GenieACS lokal';
    }
    $PRx = panel_routers();
    $panelHome = isset($PRx['panel']['url']) ? rtrim($PRx['panel']['url'], '/') . '/' : '';
    ?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($title) ?> — <?= h($S['app_name']) ?></title>
<?= fav_link() ?>
<?= theme_boot() ?>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style><?= css() ?></style>
</head>
<body>
<aside class="side" id="side">
    <div class="brand">
        <span class="logo"><?= icon('wifi') ?></span>
        <div><b><?= h(strtoupper($S['app_name'])) ?></b><small>GENIEACS PANEL</small></div>
    </div>
    <div class="side-chip"><span class="dot<?= $error ? ' bad' : '' ?>"></span><?= h(strtoupper($host)) ?></div>
    <nav class="nav">
        <?php foreach ($nav as $k => $n): ?>
            <a href="?page=<?= $k ?>" class="<?= $cur === $k ? 'on' : '' ?>"><?= icon($n[1]) ?><?= $n[0] ?></a>
        <?php endforeach; ?>
        <?php if ($panelHome): ?><a href="<?= h($panelHome) ?>" title="Kembali ke panel utama"><?= icon('back') ?><?= h(isset($PRx['panel']['name']) ? $PRx['panel']['name'] : 'Panel utama') ?></a><?php endif; ?>
    </nav>
    <div class="side-user">
        <span class="av"><?= h(strtoupper(substr($S['admin_user'], 0, 1))) ?></span>
        <div><b><?= h($S['admin_user']) ?></b><small>Administrator · v<?= h(APP_VERSION) ?></small></div>
        <a class="side-out" href="?page=logout" title="Logout" aria-label="Logout"><?= icon('logout') ?></a>
    </div>
</aside>
<div class="shade" id="shade" onclick="side(false)"></div>
<div class="wrap">
<header class="top">
    <button class="ib" id="tgMenu" onclick="side(true)" aria-label="Menu"><?= icon('menu') ?></button>
    <h1><?= h($title) ?></h1>
    <span class="sp"></span>
    <button class="ib" onclick="toggleTheme()" aria-label="Mode gelap" id="thBtn"><?= icon('moon') ?></button>
    <div class="pill"><span class="dot<?= $error ? ' bad' : '' ?>"></span><span class="lbl"><?= $error ? 'Terputus' : 'Terhubung' ?></span></div>
</header>
<main>
<?php
    if ($error) {
        echo '<div class="alert err">' . h($error) . ' — cek URL NBI di <a href="?page=settings">Settings</a>.</div>';
    }
    if ($flash) {
        list($t, $m) = explode('|', $flash, 2);
        echo '<div class="alert ' . ($t === 'ok' ? 'ok' : 'err') . '">' . h($m) . '</div>';
    }
}

function layout_end()
{
    ?>
</main>
<footer>© <?= date('Y') ?> · GenieACS Monitoring Panel</footer>
</div>
<script src="assets/chart.umd.js"></script>
<script>
var CSRF = <?= json_encode(csrf_token()) ?>;
var ICON_SUN = <?= json_encode(icon('sun')) ?>, ICON_MOON = <?= json_encode(icon('moon')) ?>;
function side(o){document.getElementById('side').classList.toggle('open',o);document.getElementById('shade').classList.toggle('open',o);}
function isDark(){return document.documentElement.getAttribute('data-theme')==='dark';}
function syncThemeIcon(){document.getElementById('thBtn').innerHTML=isDark()?ICON_SUN:ICON_MOON;}
function toggleTheme(){
    var t=isDark()?'light':'dark';document.documentElement.setAttribute('data-theme',t);
    try{localStorage.setItem('acs-theme',t);}catch(e){}
    syncThemeIcon();refreshCharts();
}
syncThemeIcon();
function toast(msg, ok){
    var t=document.createElement('div');t.className='toast'+(ok===false?' err':'');t.textContent=msg;document.body.appendChild(t);
    setTimeout(function(){t.remove();},3500);
}
function api(action, data){
    return fetch('?action='+action,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify(data||{})})
        .then(function(r){return r.json();}).catch(function(){return {ok:false,msg:'Gagal menghubungi server panel'};});
}
function act(action, data, reload){
    var btns=document.querySelectorAll('.btn');btns.forEach(function(b){b.disabled=true;});
    toast('Memproses...');
    return api(action,data).then(function(r){
        btns.forEach(function(b){b.disabled=false;});
        toast(r.msg, r.ok);
        if(r.ok && reload) setTimeout(function(){location.reload();},1500);
        return r;
    });
}
function cssVar(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim();}
var PALETTE=['#0369c7','#059669','#d97706','#dc2626','#0891b2','#7c3aed','#db2777','#65a30d','#ea580c','#475569','#0d9488','#ca8a04'];
var CHARTS=[];
function chartColors(c){
    c.data.datasets[0].backgroundColor=c.$vars?c.$vars.map(cssVar):c.data.labels.map(function(_,i){return PALETTE[i%PALETTE.length];});
    c.data.datasets[0].borderColor=cssVar('--panel');
    c.options.plugins.legend.labels.color=cssVar('--ink2');
}
function refreshCharts(){CHARTS.forEach(function(c){chartColors(c);c.update();});}
function doughnut(id, labels, data, vars){
    var el=document.getElementById(id); if(!el||!window.Chart) return;
    var total=data.reduce(function(a,b){return a+b;},0);
    var c=new Chart(el,{type:'doughnut',data:{labels:labels,datasets:[{data:data,borderWidth:3}]},
        options:{maintainAspectRatio:false,cutout:'64%',plugins:{legend:{position:'bottom',labels:{font:{family:'Inter',size:12,weight:'500'},usePointStyle:true,pointStyle:'circle',padding:16}},
        tooltip:{callbacks:{label:function(x){return ' '+x.label+': '+x.raw+' ('+(total?Math.round(x.raw/total*100):0)+'%)';}}}}}});
    c.$vars=vars;chartColors(c);c.update();CHARTS.push(c);
}
</script>
</body>
</html>
<?php
}

function render_login($S, $err, $setup = false)
{
    ?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — <?= h($S['app_name']) ?></title>
<?= fav_link() ?>
<?= theme_boot() ?>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style><?= css() ?>
body{min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 10% -10%,rgba(37,99,235,.18),transparent),var(--side);padding:20px}
.box{width:min(390px,100%);background:var(--panel);border-radius:20px;padding:30px;box-shadow:0 30px 60px rgba(2,6,23,.45)}
.box .brand{padding:0 0 22px;height:auto;justify-content:center}
.box .brand b{color:var(--ink)}
.box label{display:block;font-size:12px;font-weight:600;color:var(--ink2);margin-bottom:14px}.box input{margin-top:6px}
.box .btn{width:100%;justify-content:center;height:44px}
.box p{text-align:center;color:var(--muted);font-size:12px;margin:18px 0 0}
</style>
</head>
<body>
<form class="box" method="post">
    <div class="brand">
        <span class="logo"><?= icon('wifi') ?></span>
        <div><b><?= h(strtoupper($S['app_name'])) ?></b><small>GENIEACS PANEL</small></div>
    </div>
    <?php if ($err): ?><div class="alert err"><?= h($err) ?></div><?php endif; ?>
    <?php if ($setup): ?>
    <p style="margin:0 0 16px;color:var(--ink2);font-size:13px;text-align:left">Panel ACS baru dipasang. Buat akun admin untuk masuk.</p>
    <label>Username <input name="username" required autofocus value="admin" pattern="[A-Za-z0-9_.\-]{3,32}"></label>
    <label>Password <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
    <label>Ulangi password <input type="password" name="password2" required minlength="8" autocomplete="new-password"></label>
    <button class="btn primary" name="setup" value="1">Buat akun &amp; masuk</button>
    <?php else: ?>
    <label>Username <input name="username" required autofocus></label>
    <label>Password <input type="password" name="password" required></label>
    <button class="btn primary" name="login" value="1">Masuk</button>
    <?php endif; ?>
    <p>Panel ACS · monitoring ONT GenieACS</p>
</form>
</body>
</html>
<?php
}
