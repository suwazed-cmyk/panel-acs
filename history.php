<?php
/**
 * history.php — history redaman (RX) ONT
 *
 * - bin/collect.php (dijalankan timer tiap 15 menit) membaca RX semua ONT dari GenieACS
 *   dan menyimpannya ke tabel rx_raw (satu titik per pembacaan baru).
 * - Data lebih dari 7 hari diringkas per jam ke rx_hour, lalu dihapus dari rx_raw.
 * - rx_hour disimpan sesuai pengaturan (bawaan 90 hari).
 */

define('RX_RAW_DAYS', 7);
define('RX_PROVISION', 'panel-acs-rx');

/** Ambil RX semua ONT dan simpan titik baru. */
function rx_collect($acs, $S)
{
    $proj = implode(',', ['_id', '_lastInform', 'VirtualParameters', 'InternetGatewayDevice.WANDevice.1', 'Device.Optical']);
    $devs = $acs->devices([], $proj);
    if ($acs->lastError && !$devs) {
        return ['ok' => false, 'error' => $acs->lastError];
    }
    $pdo = db();
    $last = [];
    foreach ($pdo->query('SELECT dev, MAX(ts) AS ts FROM rx_raw GROUP BY dev') as $r) {
        $last[$r['dev']] = (int) $r['ts'];
    }
    $P = acs_params();
    $ins = $pdo->prepare('INSERT OR IGNORE INTO rx_raw (dev, ts, rx, temp) VALUES (?, ?, ?, ?)');
    $n = 0;
    $pdo->beginTransaction();
    foreach ($devs as $d) {
        list($rx, $ts) = rx_point($d);
        if ($rx === null || !$ts) {
            continue;
        }
        $id = $d['_id'];
        // Simpan hanya bila nilai RX benar-benar dibaca ulang oleh GenieACS
        if (isset($last[$id]) && $ts <= $last[$id]) {
            continue;
        }
        $t = acs_first($d, $P['temp']);
        $ins->execute([$id, $ts, $rx, is_numeric($t) ? round((float) $t, 1) : null]);
        $n++;
    }
    $pdo->commit();
    $pr = rx_prune($S);
    cache_set('collect', ['at' => time(), 'devices' => count($devs), 'saved' => $n]);
    return ['ok' => true, 'devices' => count($devs), 'saved' => $n, 'hourly' => $pr];
}

/** Ringkas data lama per jam lalu hapus; buang ringkasan yang melewati masa simpan. */
function rx_prune($S)
{
    $pdo = db();
    $cut = time() - RX_RAW_DAYS * 86400;
    $cut -= $cut % 3600;
    $pdo->beginTransaction();
    $pdo->prepare('
        INSERT OR REPLACE INTO rx_hour (dev, hour, avg, min, max, n)
        SELECT dev, (ts / 3600) * 3600 AS hour, AVG(rx), MIN(rx), MAX(rx), COUNT(*)
        FROM rx_raw WHERE ts < ? GROUP BY dev, hour
    ')->execute([$cut]);
    $pdo->prepare('DELETE FROM rx_raw WHERE ts < ?')->execute([$cut]);
    $keep = max(14, min(730, (int) (isset($S['rx_keep_days']) ? $S['rx_keep_days'] : 90)));
    $pdo->prepare('DELETE FROM rx_hour WHERE hour < ?')->execute([time() - $keep * 86400]);
    $pdo->commit();
    return true;
}

/** Titik grafik untuk satu ONT. range: 1d, 7d, 30d, 90d */
function rx_series($dev, $range)
{
    $days = ['1d' => 1, '7d' => 7, '30d' => 30, '90d' => 90];
    $d = isset($days[$range]) ? $days[$range] : 7;
    $from = time() - $d * 86400;
    $pdo = db();
    $pts = [];
    if ($d > RX_RAW_DAYS) {
        $st = $pdo->prepare('SELECT hour AS ts, avg AS rx, min, max FROM rx_hour WHERE dev = ? AND hour >= ? ORDER BY hour');
        $st->execute([$dev, $from]);
        foreach ($st as $r) {
            $pts[] = ['t' => (int) $r['ts'], 'rx' => round((float) $r['rx'], 2), 'min' => (float) $r['min'], 'max' => (float) $r['max']];
        }
    }
    $st = $pdo->prepare('SELECT ts, rx FROM rx_raw WHERE dev = ? AND ts >= ? ORDER BY ts');
    $st->execute([$dev, $from]);
    $raw = $st->fetchAll();
    // Rentang panjang: data mentah diringkas per jam supaya grafik tetap ringan
    if ($d > RX_RAW_DAYS) {
        $bucket = [];
        foreach ($raw as $r) {
            $h = (int) $r['ts'] - ((int) $r['ts'] % 3600);
            $bucket[$h][] = (float) $r['rx'];
        }
        foreach ($bucket as $h => $v) {
            $pts[] = ['t' => $h, 'rx' => round(array_sum($v) / count($v), 2), 'min' => min($v), 'max' => max($v)];
        }
    } else {
        foreach ($raw as $r) {
            $pts[] = ['t' => (int) $r['ts'], 'rx' => (float) $r['rx']];
        }
    }
    $vals = array_column($pts, 'rx');
    return [
        'points' => $pts,
        'stats'  => $vals ? ['min' => min(array_column($pts, isset($pts[0]['min']) ? 'min' : 'rx')), 'max' => max(array_column($pts, isset($pts[0]['max']) ? 'max' : 'rx')), 'avg' => round(array_sum($vals) / count($vals), 2), 'n' => count($vals)] : null,
    ];
}

/**
 * Perubahan RX 24 jam per ONT: nilai terbaru dikurangi rata-rata 22–26 jam lalu.
 * Negatif = redaman memburuk.
 */
function rx_delta24()
{
    $pdo = db();
    $now = time();
    $old = [];
    $st = $pdo->prepare('SELECT dev, AVG(rx) AS rx FROM rx_raw WHERE ts BETWEEN ? AND ? GROUP BY dev');
    $st->execute([$now - 26 * 3600, $now - 22 * 3600]);
    foreach ($st as $r) {
        $old[$r['dev']] = (float) $r['rx'];
    }
    $out = [];
    if (!$old) {
        return $out;
    }
    $st = $pdo->prepare('SELECT r.dev, r.rx FROM rx_raw r JOIN (SELECT dev, MAX(ts) AS ts FROM rx_raw WHERE ts >= ? GROUP BY dev) m ON m.dev = r.dev AND m.ts = r.ts');
    $st->execute([$now - 6 * 3600]);
    foreach ($st as $r) {
        if (isset($old[$r['dev']])) {
            $out[$r['dev']] = round((float) $r['rx'] - $old[$r['dev']], 2);
        }
    }
    return $out;
}

function rx_status()
{
    $pdo = db();
    $c = cache_get('collect', PHP_INT_MAX);
    return [
        'last'   => $c ? $c['v'] : null,
        'points' => (int) $pdo->query('SELECT COUNT(*) FROM rx_raw')->fetchColumn() + (int) $pdo->query('SELECT COUNT(*) FROM rx_hour')->fetchColumn(),
        'devs'   => (int) $pdo->query('SELECT COUNT(DISTINCT dev) FROM rx_raw')->fetchColumn(),
        'since'  => (int) $pdo->query('SELECT MIN(t) FROM (SELECT MIN(ts) AS t FROM rx_raw UNION SELECT MIN(hour) FROM rx_hour)')->fetchColumn(),
        'size'   => file_exists(DB_FILE) ? filesize(DB_FILE) : 0,
    ];
}

/**
 * Provision tambahan agar GenieACS membaca ulang RX setiap Inform berkala.
 * Hanya path RX yang memang ada di ONT yang dibaca ulang; provision lain tidak diubah.
 */
function rx_provision_script()
{
    $P = acs_params();
    // Path vendor lebih dulu; VirtualParameters terakhir (skripnya bisa membaca dengan jadwal sendiri)
    $paths = array_merge(
        array_values(array_filter($P['rx'], function ($p) { return strpos($p, 'VirtualParameters.') !== 0; })),
        array_values(array_filter($P['rx'], function ($p) { return strpos($p, 'VirtualParameters.') === 0; }))
    );
    $list = json_encode($paths, JSON_UNESCAPED_SLASHES);
    return "// Dibuat oleh Panel ACS: baca ulang redaman (RX) setiap Inform untuk history grafik.\n"
        . "// Aman dihapus dari Panel ACS → Settings → History redaman.\n"
        . "const paths = $list;\n"
        . "const fresh = Date.now() - 4 * 60 * 1000;\n"
        . "for (const p of paths) {\n"
        . "  const cur = declare(p, {value: 1});\n"
        . "  if (cur.size) {\n"
        . "    declare(p, {value: fresh});\n"
        . "    break;\n"
        . "  }\n"
        . "}\n";
}
function rx_provision_install($acs)
{
    if (!$acs->putProvision(RX_PROVISION, rx_provision_script())) {
        return ['ok' => false, 'msg' => 'Gagal membuat provision: ' . $acs->lastError];
    }
    $preset = [
        'weight'         => 100,
        'channel'        => 'panel-acs',
        'events'         => ['2 PERIODIC' => true],
        'precondition'   => '',
        'configurations' => [['type' => 'provision', 'name' => RX_PROVISION, 'args' => null]],
    ];
    if (!$acs->putPreset(RX_PROVISION, $preset)) {
        $acs->deleteItem('provisions', RX_PROVISION);
        return ['ok' => false, 'msg' => 'Gagal membuat preset: ' . $acs->lastError];
    }
    return ['ok' => true, 'msg' => 'Provision RX dipasang. RX dibaca ulang setiap Inform berkala (mulai Inform berikutnya).'];
}
function rx_provision_remove($acs)
{
    $a = $acs->deleteItem('presets', RX_PROVISION);
    $b = $acs->deleteItem('provisions', RX_PROVISION);
    return ($a && $b)
        ? ['ok' => true, 'msg' => 'Provision RX dihapus. RX kembali mengikuti jadwal provision bawaan.']
        : ['ok' => false, 'msg' => 'Gagal menghapus: ' . $acs->lastError];
}
