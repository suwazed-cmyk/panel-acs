<?php
/**
 * Menyiapkan database (dipanggil saat add-on dipasang/diperbarui, aman diulang).
 * Data lama (settings.json, locations.json) diimpor otomatis.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}
require __DIR__ . '/../config.php';
$pdo = db();
$v = (int) $pdo->query('PRAGMA user_version')->fetchColumn();
$n = (int) $pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn();
echo "Database siap (skema v$v, $n pengaturan tersimpan)\n";
$link = panel_link();
echo $link ? "Terhubung ke panel utama di {$link['url']}\n" : "Belum terhubung ke panel utama (dipasang mandiri)\n";
