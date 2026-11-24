<?php
/**
 * Pencatat redaman ONT. Dijalankan berkala oleh timer systemd add-on
 * (addon-panel-acs-collect.timer, tiap 15 menit) atau cron di hosting:
 *   php /path/panel-acs/bin/collect.php
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}
require __DIR__ . '/../config.php';
require __DIR__ . '/../genieacs.php';
require __DIR__ . '/../history.php';

$S = load_settings();
@date_default_timezone_set($S['timezone'] ?: 'Asia/Makassar');
// Kunci supaya dua proses tidak berjalan bersamaan
$lock = fopen(DATA_DIR . '/collect.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "Pencatat masih berjalan, dilewati.\n");
    exit(0);
}
$t0 = microtime(true);
$r = rx_collect(new GenieACS($S), $S);
if (!$r['ok']) {
    fwrite(STDERR, 'Gagal membaca GenieACS: ' . $r['error'] . "\n");
    exit(1);
}
printf("%d ONT dibaca, %d titik redaman baru disimpan (%.1f dtk)\n", $r['devices'], $r['saved'], microtime(true) - $t0);
