<?php
/**
 * genieacs.php — klien API NBI GenieACS + helper pembaca parameter
 */

class GenieACS
{
    private $base;
    private $user;
    private $pass;
    public $lastError = '';

    public function __construct($settings)
    {
        $this->base = rtrim($settings['acs_url'], '/');
        $this->user = $settings['acs_user'];
        $this->pass = $settings['acs_pass'];
    }

    public function request($method, $path, $body = null, &$code = null)
    {
        $this->lastError = '';
        $ch = curl_init($this->base . $path);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 40,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
        ];
        if ($this->user !== '') {
            $opts[CURLOPT_USERPWD] = $this->user . ':' . $this->pass;
        }
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = is_string($body) ? $body : json_encode($body);
        }
        curl_setopt_array($ch, $opts);
        $res  = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($res === false) {
            $this->lastError = 'Tidak bisa terhubung ke GenieACS: ' . curl_error($ch);
            curl_close($ch);
            return null;
        }
        curl_close($ch);
        if ($code >= 400) {
            $this->lastError = 'GenieACS HTTP ' . $code . ': ' . substr(trim($res), 0, 200);
        }
        $json = json_decode($res, true);
        return $json === null ? $res : $json;
    }

    public function devices($query = [], $projection = '')
    {
        $qs = 'query=' . rawurlencode(json_encode((object) $query));
        if ($projection !== '') {
            $qs .= '&projection=' . rawurlencode($projection);
        }
        $r = $this->request('GET', '/devices/?' . $qs, null, $code);
        return ($code === 200 && is_array($r)) ? $r : [];
    }

    public function device($id)
    {
        $r = $this->devices(['_id' => $id]);
        return isset($r[0]) ? $r[0] : null;
    }

    /** Buat/ubah provision (skrip). */
    public function putProvision($name, $script)
    {
        $this->request('PUT', '/provisions/' . rawurlencode($name), $script, $code);
        return $code === 200;
    }

    /** Buat/ubah preset. */
    public function putPreset($name, $preset)
    {
        $this->request('PUT', '/presets/' . rawurlencode($name), $preset, $code);
        return $code === 200;
    }

    public function deleteItem($kind, $name)
    {
        $this->request('DELETE', '/' . $kind . '/' . rawurlencode($name), null, $code);
        return $code === 200 || $code === 404;
    }

    public function exists($kind, $name)
    {
        $r = $this->request('GET', '/' . $kind . '/?query=' . rawurlencode(json_encode(['_id' => $name])), null, $code);
        return $code === 200 && is_array($r) && count($r) > 0;
    }

    public function faults()
    {
        $r = $this->request('GET', '/faults/', null, $code);
        return ($code === 200 && is_array($r)) ? $r : [];
    }

    public function deleteFault($id)
    {
        $this->request('DELETE', '/faults/' . rawurlencode($id), null, $code);
        return $code === 200;
    }

    public function task($deviceId, $task)
    {
        $path = '/devices/' . rawurlencode($deviceId) . '/tasks?timeout=5000&connection_request';
        $this->request('POST', $path, $task, $code);
        if ($code === 200) {
            return ['ok' => true, 'msg' => 'Berhasil dijalankan di perangkat.'];
        }
        if ($code === 202) {
            return ['ok' => true, 'msg' => 'Task masuk antrian. Akan dijalankan saat perangkat inform berikutnya.'];
        }
        return ['ok' => false, 'msg' => $this->lastError ?: ('Gagal, HTTP ' . $code)];
    }

    public function addTag($deviceId, $tag)
    {
        $this->request('POST', '/devices/' . rawurlencode($deviceId) . '/tags/' . rawurlencode($tag), null, $code);
        return $code === 200;
    }

    public function removeTag($deviceId, $tag)
    {
        $this->request('DELETE', '/devices/' . rawurlencode($deviceId) . '/tags/' . rawurlencode($tag), null, $code);
        return $code === 200;
    }
}

/* ================= Helper parameter ================= */

/** Daftar path yang dicoba berurutan (VirtualParameters dulu, lalu per merk). */
function acs_params()
{
    static $p = null;
    if ($p !== null) {
        return $p;
    }
    $igdWan = 'InternetGatewayDevice.WANDevice.1';
    $p = [
        'rx' => [
            'VirtualParameters.RXPower',
            'VirtualParameters.redaman',
            'VirtualParameters.rxpower',
            $igdWan . '.X_FH_GponInterfaceConfig.RXPower',
            $igdWan . '.X_GponInterafceConfig.RXPower',
            $igdWan . '.X_GponInterfaceConfig.RXPower',
            $igdWan . '.X_ZTE-COM_WANPONInterfaceConfig.RXPower',
            $igdWan . '.X_CT-COM_GponInterfaceConfig.RXPower',
            $igdWan . '.X_CMCC_GponInterfaceConfig.RXPower',
            $igdWan . '.X_CU_WANEPONInterfaceConfig.OpticalTransceiver.RXPower',
            'Device.Optical.Interface.1.RxPower',
            'Device.Optical.Interface.1.OpticalSignalLevel',
        ],
        'temp' => [
            'VirtualParameters.gettemp',
            'VirtualParameters.temperature',
            $igdWan . '.X_FH_GponInterfaceConfig.TransceiverTemperature',
            $igdWan . '.X_GponInterafceConfig.TransceiverTemperature',
            $igdWan . '.X_ZTE-COM_WANPONInterfaceConfig.Temperature',
            $igdWan . '.X_CT-COM_GponInterfaceConfig.TransceiverTemperature',
        ],
        'pppoe' => [
            'VirtualParameters.pppoeUsername',
            'VirtualParameters.pppoeUsername2',
            $igdWan . '.WANConnectionDevice.*.WANPPPConnection.*.Username',
            'Device.PPP.Interface.*.Username',
        ],
        'ip' => [
            'VirtualParameters.pppoeIP',
            $igdWan . '.WANConnectionDevice.*.WANPPPConnection.*.ExternalIPAddress',
        ],
        'tr069' => [
            'VirtualParameters.IPTR069',
            'VirtualParameters.iptr069',
            'VirtualParameters.ipTR069',
        ],
        'mac' => [
            'VirtualParameters.PonMac',
            'VirtualParameters.ponMac',
            $igdWan . '.WANConnectionDevice.*.WANIPConnection.*.MACAddress',
            'VirtualParameters.pppoeMac',
            $igdWan . '.WANConnectionDevice.*.WANPPPConnection.*.MACAddress',
        ],
        'ssid' => [
            'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID',
            'Device.WiFi.SSID.1.SSID',
        ],
        'uptime' => [
            'VirtualParameters.getdeviceuptime',
            'InternetGatewayDevice.DeviceInfo.UpTime',
            'Device.DeviceInfo.UpTime',
        ],
        'sw' => [
            'InternetGatewayDevice.DeviceInfo.SoftwareVersion',
            'Device.DeviceInfo.SoftwareVersion',
        ],
        'hw' => [
            'InternetGatewayDevice.DeviceInfo.HardwareVersion',
            'Device.DeviceInfo.HardwareVersion',
        ],
    ];
    return $p;
}

/** Projection untuk daftar perangkat (agar respon ringan). */
function acs_list_projection()
{
    return implode(',', [
        '_id', '_lastInform', '_registered', '_lastBoot', '_lastBootstrap', '_deviceId', '_tags',
        'VirtualParameters',
        'InternetGatewayDevice.ManagementServer.ConnectionRequestURL',
        'Device.ManagementServer.ConnectionRequestURL',
        'InternetGatewayDevice.ManagementServer.PeriodicInformInterval',
        'Device.ManagementServer.PeriodicInformInterval',
        'InternetGatewayDevice.DeviceInfo.UpTime',
        'InternetGatewayDevice.DeviceInfo.SoftwareVersion',
        'InternetGatewayDevice.DeviceInfo.HardwareVersion',
        'InternetGatewayDevice.WANDevice.1',
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration',
        'Device.DeviceInfo.UpTime',
        'Device.DeviceInfo.SoftwareVersion',
        'Device.DeviceInfo.HardwareVersion',
        'Device.Optical',
        'Device.PPP',
        'Device.IP.Interface',
        'Device.WiFi.SSID',
        'Device.WiFi.AccessPoint',
    ]);
}

function acs_walk($node, $parts, $i)
{
    if (!is_array($node)) {
        return null;
    }
    if ($i === count($parts)) {
        return $node;
    }
    $p = $parts[$i];
    if ($p === '*') {
        foreach ($node as $k => $child) {
            $k = (string) $k;
            if ($k === '' || $k[0] === '_') {
                continue;
            }
            $v = acs_walk($child, $parts, $i + 1);
            if ($v !== null && !(is_array($v) && array_key_exists('_value', $v) && ($v['_value'] === '' || $v['_value'] === null))) {
                return $v;
            }
        }
        return null;
    }
    return isset($node[$p]) ? acs_walk($node[$p], $parts, $i + 1) : null;
}

/** Ambil node (array) pada path; mendukung wildcard "*". */
function acs_node($dev, $path)
{
    return acs_walk($dev, explode('.', $path), 0);
}

/** Ambil nilai _value pada path. */
function acs_get($dev, $path)
{
    $n = acs_node($dev, $path);
    return (is_array($n) && array_key_exists('_value', $n)) ? $n['_value'] : null;
}

/** Ambil nilai pertama yang ada dari beberapa path. */
function acs_first($dev, $paths)
{
    foreach ($paths as $p) {
        $v = acs_get($dev, $p);
        if ($v !== null && $v !== '') {
            return $v;
        }
    }
    return null;
}

function acs_ts($v)
{
    if (!$v) {
        return 0;
    }
    $t = strtotime($v);
    return $t ? $t : 0;
}

/** Konversi nilai RX ke dBm. Nilai positif dianggap satuan 0.1 µW (umum di ZTE). */
function rx_dbm($v)
{
    if ($v === null || $v === '') {
        return null;
    }
    if (!is_numeric($v)) {
        if (!preg_match('/-?\d+(\.\d+)?/', (string) $v, $m)) {
            return null;
        }
        $v = $m[0];
    }
    $v = (float) $v;
    if ($v <= 0 && $v > -60) {
        return round($v, 2);
    }
    if ($v > 0) {
        return round(10 * log10($v / 10000), 2);
    }
    return null;
}

function rx_class($rx, $S)
{
    if ($rx === null) {
        return 'na';
    }
    if ($rx >= (float) $S['rx_good']) {
        return 'good';
    }
    if ($rx >= (float) $S['rx_fair']) {
        return 'fair';
    }
    return 'poor';
}

function wlan_clients($dev)
{
    $vp = acs_first($dev, ['VirtualParameters.activedevices', 'VirtualParameters.userconnected']);
    if ($vp !== null && is_numeric($vp)) {
        return (int) $vp;
    }
    $total = null;
    $wl = acs_node($dev, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration');
    if (is_array($wl)) {
        foreach ($wl as $k => $w) {
            if (is_array($w) && ((string) $k)[0] !== '_') {
                $n = wlan_assoc($w);
                if ($n !== null) {
                    $total = (int) $total + $n;
                }
            }
        }
    }
    $ap = acs_node($dev, 'Device.WiFi.AccessPoint');
    if (is_array($ap)) {
        foreach ($ap as $k => $a) {
            if (is_array($a) && isset($a['AssociatedDeviceNumberOfEntries']['_value'])) {
                $total = (int) $total + (int) $a['AssociatedDeviceNumberOfEntries']['_value'];
            }
        }
    }
    return $total;
}

function fmt_uptime($sec)
{
    if ($sec === null || $sec === '' || !is_numeric($sec)) {
        return $sec ? (string) $sec : '-';
    }
    $sec = (int) $sec;
    $d = intdiv($sec, 86400);
    $h = intdiv($sec % 86400, 3600);
    $m = intdiv($sec % 3600, 60);
    return ($d ? $d . 'h ' : '') . $h . 'j ' . $m . 'm';
}

function ago($ts)
{
    if (!$ts) {
        return '-';
    }
    $d = time() - $ts;
    if ($d < 60) {
        return $d . ' dtk lalu';
    }
    if ($d < 3600) {
        return floor($d / 60) . ' mnt lalu';
    }
    if ($d < 86400) {
        return floor($d / 3600) . ' jam lalu';
    }
    return floor($d / 86400) . ' hari lalu';
}

/** Deteksi band SSID: OperatingFrequencyBand, channel, Standard, nama, lalu nomor urut (1-4 = 2.4 GHz, 5-8 = 5 GHz). Hasil: '2.4' atau '5'. */
function wlan_band($idx, $w, $max)
{
    $g = function ($k) use ($w) {
        return isset($w[$k]['_value']) ? (string) $w[$k]['_value'] : '';
    };
    $f = strtolower($g('OperatingFrequencyBand'));
    if ($f !== '') {
        if (strpos($f, '2.4') !== false || strpos($f, '2,4') !== false) {
            return '2.4';
        }
        if (strpos($f, '5') !== false) {
            return '5';
        }
    }
    $ch = $g('Channel');
    if (is_numeric($ch) && (int) $ch > 0) {
        return (int) $ch > 14 ? '5' : '2.4';
    }
    $st = strtolower($g('Standard'));
    if ($st !== '') {
        if (strpos($st, 'ac') !== false || preg_match('/(^|[^a-z])a([^a-z]|$)/', $st)) {
            return '5';
        }
        if (preg_match('/[bg]/', $st)) {
            return '2.4';
        }
    }
    if (preg_match('/(^|[^0-9])5\s?g/i', $g('SSID'))) {
        return '5';
    }
    if ($max > 4 && (int) $idx > $max / 2) {
        return '5';
    }
    return '2.4';
}

/** SSID aktif pertama per band: ['2.4' => '...', '5' => '...']. */
function ssid_bands($d)
{
    $out = ['2.4' => '', '5' => ''];
    foreach (['InternetGatewayDevice.LANDevice.1.WLANConfiguration', 'Device.WiFi.SSID'] as $base) {
        $wl = acs_node($d, $base);
        if (!is_array($wl)) {
            continue;
        }
        $max = 0;
        foreach ($wl as $k => $w) {
            if (is_array($w) && ((string) $k)[0] !== '_') {
                $max = max($max, (int) $k);
            }
        }
        foreach ($wl as $k => $w) {
            if (!is_array($w) || ((string) $k)[0] === '_') {
                continue;
            }
            $ssid = isset($w['SSID']['_value']) ? (string) $w['SSID']['_value'] : '';
            $en = isset($w['Enable']['_value']) ? $w['Enable']['_value'] : null;
            if ($ssid === '' || $en === false || $en === 0 || $en === '0' || (is_string($en) && strtolower($en) === 'false')) {
                continue;
            }
            $b = wlan_band($k, $w, $max);
            if ($out[$b] === '') {
                $out[$b] = $ssid;
            }
        }
    }
    return $out;
}

/** Jumlah klien satu SSID (TotalAssociations / WLAN_AssociatedDeviceNumberOfEntries FiberHome / daftar AssociatedDevice). */
function wlan_assoc($w)
{
    $n = null;
    foreach (['TotalAssociations', 'WLAN_AssociatedDeviceNumberOfEntries', 'AssociatedDeviceNumberOfEntries'] as $k) {
        if (isset($w[$k]['_value']) && $w[$k]['_value'] !== '' && is_numeric($w[$k]['_value'])) {
            $n = (int) $w[$k]['_value'];
            break;
        }
    }
    if (isset($w['AssociatedDevice']) && is_array($w['AssociatedDevice'])) {
        $c = 0;
        foreach ($w['AssociatedDevice'] as $ak => $a) {
            if (is_array($a) && ((string) $ak)[0] !== '_' && !empty($a['AssociatedDeviceMACAddress']['_value'])) {
                $c++;
            }
        }
        if ($c > 0 && ($n === null || $c > $n)) {
            $n = $c;
        }
    }
    return $n;
}

/** MAC pertama yang bukan 00:00:00:00:00:00. */
function mac_first($d, $paths)
{
    foreach ($paths as $p) {
        $v = acs_get($d, $p);
        if ($v !== null && $v !== '' && !preg_match('/^(0{1,2}[:\-]?){5}0{1,2}$/', (string) $v)) {
            return (string) $v;
        }
    }
    return '';
}

/** Interval periodic inform (detik), 0 jika tidak diketahui. */
function inform_interval($d)
{
    $v = acs_first($d, ['InternetGatewayDevice.ManagementServer.PeriodicInformInterval', 'Device.ManagementServer.PeriodicInformInterval']);
    return (is_numeric($v) && $v > 0) ? (int) $v : 0;
}

/** Batas detik sebelum dianggap offline: otomatis 2x interval inform + 60 detik, atau manual dari Settings. */
function online_limit($d, $S)
{
    $iv = inform_interval($d);
    if ((!isset($S['online_auto']) || $S['online_auto']) && $iv > 0) {
        return $iv * 2 + 60;
    }
    return (int) $S['online_minutes'] * 60;
}

/** IP manajemen TR-069: dari ConnectionRequestURL, lalu VirtualParameters.IPTR069. */
function tr069_ip($d)
{
    $url = acs_first($d, ['InternetGatewayDevice.ManagementServer.ConnectionRequestURL', 'Device.ManagementServer.ConnectionRequestURL']);
    if ($url) {
        $host = parse_url((string) $url, PHP_URL_HOST);
        if ($host) {
            return trim($host, '[]');
        }
    }
    $P = acs_params();
    $v = acs_first($d, $P['tr069']);
    return $v !== null ? (string) $v : '';
}

/** Tampilkan tag dengan spasi (garis bawah diubah jadi spasi). */
function tag_text($t)
{
    return str_replace('_', ' ', (string) $t);
}

/** Deteksi merek ONT dari manufacturer, serial, product class, dan OUI. */
function detect_brand($vendor, $pc, $serial, $oui)
{
    $txt = strtolower($vendor . ' ' . $pc);
    $byName = [
        'fiberhome' => 'FiberHome', 'fiber home' => 'FiberHome', 'zte' => 'ZTE', 'huawei' => 'Huawei',
        'c-data' => 'C-Data', 'cdata' => 'C-Data', 'nokia' => 'Nokia', 'alcatel' => 'Nokia',
        'tp-link' => 'TP-Link', 'tplink' => 'TP-Link', 'bdcom' => 'BDCOM', 'v-sol' => 'V-SOL', 'vsol' => 'V-SOL',
        'hsgq' => 'HSGQ', 'raisecom' => 'Raisecom', 'totolink' => 'Totolink', 'tenda' => 'Tenda',
        'zyxel' => 'Zyxel', 'sagemcom' => 'Sagemcom', 'optilink' => 'Optilink', 'xiaomi' => 'Xiaomi',
    ];
    foreach ($byName as $k => $b) {
        if (strpos($txt, $k) !== false) {
            return $b;
        }
    }
    $sp = strtoupper(substr((string) $serial, 0, 4));
    $bySerial = [
        'FHTT' => 'FiberHome', 'ZTEG' => 'ZTE', 'ZICG' => 'ZTE', 'HWTC' => 'Huawei', '4857' => 'Huawei',
        'CDTC' => 'C-Data', 'ALCL' => 'Nokia', 'TPLG' => 'TP-Link', 'VSOL' => 'V-SOL', 'HSGQ' => 'HSGQ',
    ];
    if (isset($bySerial[$sp])) {
        return $bySerial[$sp];
    }
    $p = strtoupper((string) $pc);
    if (preg_match('/^(HG6|HG2|AN5|SR1)/', $p)) {
        return 'FiberHome';
    }
    if (preg_match('/^(HG8|EG8|HS8|HN8)/', $p)) {
        return 'Huawei';
    }
    if (preg_match('/^F[46]\d\d/', $p)) {
        return 'ZTE';
    }
    if (preg_match('/^FD\d/', $p)) {
        return 'C-Data';
    }
    $byOui = ['000AC2' => 'FiberHome', '00259E' => 'Huawei', 'E0A1D7' => 'ZTE'];
    $o = strtoupper((string) $oui);
    if (isset($byOui[$o])) {
        return $byOui[$o];
    }
    $v = trim((string) $vendor);
    return ($v !== '' && $v !== '-') ? $v : 'Lainnya';
}

if (!defined('GROUPS_FILE')) {
    define('GROUPS_FILE', DATA_DIR . '/groups.json');
}

/** Ubah nilai uptime (detik, atau format "0d 22:47:45") menjadi detik. */
function uptime_secs_val($v)
{
    if (is_numeric($v)) {
        return (int) $v;
    }
    if (preg_match('/(\d+)\s*d\D+(\d+):(\d+):(\d+)/i', (string) $v, $m)) {
        return $m[1] * 86400 + $m[2] * 3600 + $m[3] * 60 + $m[4];
    }
    return null;
}

/** Perkiraan waktu ONT terakhir menyala (boot), dari _lastBoot atau uptime + timestamp parameter. */
function boot_time($d)
{
    $best = 0;
    $bt = 0;
    foreach (['InternetGatewayDevice.DeviceInfo.UpTime', 'Device.DeviceInfo.UpTime', 'VirtualParameters.getdeviceuptime'] as $p) {
        $n = acs_node($d, $p);
        if (!is_array($n) || !isset($n['_value'])) {
            continue;
        }
        $secs = uptime_secs_val($n['_value']);
        $ts = isset($n['_timestamp']) ? acs_ts($n['_timestamp']) : 0;
        if ($secs === null || !$ts) {
            continue;
        }
        if ($ts > $best) {
            $best = $ts;
            $bt = $ts - $secs;
        }
    }
    $lb = acs_ts(isset($d['_lastBoot']) ? $d['_lastBoot'] : null);
    return max($lb, $bt);
}

/** Durasi singkat: 45 dtk, 12 mnt, 3j 5m, 2h 4j. */
function dur_fmt($s)
{
    $s = max(0, (int) $s);
    if ($s < 60) {
        return $s . ' dtk';
    }
    if ($s < 3600) {
        return floor($s / 60) . ' mnt';
    }
    if ($s < 86400) {
        return floor($s / 3600) . 'j ' . floor(($s % 3600) / 60) . 'm';
    }
    return floor($s / 86400) . 'h ' . floor(($s % 86400) / 3600) . 'j';
}

/** Label Up/Down dari data GenieACS: online = sejak restart terakhir, offline = sejak komunikasi terakhir. */
function updown($d)
{
    if ($d['online']) {
        $since = (int) $d['boot'];
        return $since ? '<span class="ud up" title="Online sejak ' . date('d M Y H:i', $since) . '">▲ ' . dur_fmt(time() - $since) . '</span>' : '<span class="ud up">▲</span>';
    }
    $since = (int) $d['last'];
    return $since ? '<span class="ud down" title="Offline sejak ' . date('d M Y H:i', $since) . '">▼ ' . dur_fmt(time() - $since) . '</span>' : '<span class="ud down">▼</span>';
}

/**
 * Pisahkan tag menjadi [area, nama, sisa].
 * Konvensi: tag 1 = area/kelompok (mis. ODP atau dusun), tag 2 = nama pelanggan.
 * Jika hanya ada satu tag, tag itu dianggap nama pelanggan.
 * Router TIDAK lagi diambil dari tag, tetapi dari panel utama (IP virtual).
 */
function tags_split($tags)
{
    $tags = array_values(array_map('strval', is_array($tags) ? $tags : []));
    if (count($tags) >= 2) {
        return [$tags[0], $tags[1], array_slice($tags, 2)];
    }
    return ['', isset($tags[0]) ? $tags[0] : '', []];
}

/** Nilai RX beserta waktu pembacaannya (dari _timestamp parameter GenieACS). */
function rx_point($d)
{
    $P = acs_params();
    foreach ($P['rx'] as $path) {
        $n = acs_node($d, $path);
        if (is_array($n) && array_key_exists('_value', $n) && $n['_value'] !== '' && $n['_value'] !== null) {
            $rx = rx_dbm($n['_value']);
            if ($rx === null) {
                continue;
            }
            $ts = isset($n['_timestamp']) ? acs_ts($n['_timestamp']) : 0;
            return [$rx, $ts ?: acs_ts(isset($d['_lastInform']) ? $d['_lastInform'] : null)];
        }
    }
    return [null, 0];
}

/** Ringkas satu perangkat menjadi array datar. */
function normalize_device($d, $S)
{
    $P   = acs_params();
    $did = isset($d['_deviceId']) ? $d['_deviceId'] : [];
    $last = acs_ts(isset($d['_lastInform']) ? $d['_lastInform'] : null);
    $rx  = rx_dbm(acs_first($d, $P['rx']));
    $temp = acs_first($d, $P['temp']);
    $tags = isset($d['_tags']) && is_array($d['_tags']) ? array_values($d['_tags']) : [];
    $sb = ssid_bands($d);
    list($areaT, $nameT, $restT) = tags_split($tags);
    $ip = tr069_ip($d);
    $router = $ip !== '' ? router_for_ip($ip) : null;
    $linked = panel_routers()['linked'];
    return [
        'id'         => $d['_id'],
        'serial'     => isset($did['_SerialNumber']) ? $did['_SerialNumber'] : '-',
        'pc'         => isset($did['_ProductClass']) ? $did['_ProductClass'] : '-',
        'vendor'     => isset($did['_Manufacturer']) ? $did['_Manufacturer'] : '-',
        'oui'        => isset($did['_OUI']) ? $did['_OUI'] : '-',
        'brand'      => detect_brand(isset($did['_Manufacturer']) ? $did['_Manufacturer'] : '', isset($did['_ProductClass']) ? $did['_ProductClass'] : '', isset($did['_SerialNumber']) ? $did['_SerialNumber'] : '', isset($did['_OUI']) ? $did['_OUI'] : ''),
        'last'       => $last,
        'registered' => acs_ts(isset($d['_registered']) ? $d['_registered'] : null),
        'lastBoot'   => acs_ts(isset($d['_lastBoot']) ? $d['_lastBoot'] : null),
        'bootstrap'  => acs_ts(isset($d['_lastBootstrap']) ? $d['_lastBootstrap'] : null),
        'online'     => $last && (time() - $last) <= online_limit($d, $S),
        'rx'         => $rx,
        'rxc'        => rx_class($rx, $S),
        'temp'       => ($temp !== null && is_numeric($temp)) ? round((float) $temp, 1) : $temp,
        'pppoe'      => (string) acs_first($d, $P['pppoe']),
        'ip'         => $ip,
        'ip_pppoe'   => (string) acs_first($d, $P['ip']),
        'mac'        => mac_first($d, $P['mac']),
        'ssid'       => $sb['2.4'] !== '' ? $sb['2.4'] : ($sb['5'] !== '' ? '' : (string) acs_first($d, $P['ssid'])),
        'ssid5'      => $sb['5'],
        'clients'    => wlan_clients($d),
        'uptime'     => acs_first($d, $P['uptime']),
        'boot'       => boot_time($d),
        'sw'         => (string) acs_first($d, $P['sw']),
        'hw'         => (string) acs_first($d, $P['hw']),
        'ponmode'    => (string) acs_first($d, ['VirtualParameters.getponmode', 'InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.WANAccessType']),
        'pppuptime'  => (string) acs_first($d, ['VirtualParameters.getpppuptime']),
        'inform_iv'  => inform_interval($d),
        'tags'       => $tags,
        // "group" = router dari panel utama; tanpa panel utama memakai area (tag 1)
        'group'      => $linked ? ($router ? $router['name'] : '') : tag_text($areaT),
        'router_id'  => $router ? $router['id'] : '',
        'router_on'  => $router ? !empty($router['online']) : null,
        'router_tr'  => $router ? $router['transport'] : '',
        'area'       => tag_text($areaT),
        'area_raw'   => $areaT,
        'name'       => tag_text($nameT),
        'tags_rest'  => $restT,
        'tr181'      => !isset($d['InternetGatewayDevice']) && isset($d['Device']),
    ];
}
