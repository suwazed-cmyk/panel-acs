<?php
/**
 * Router untuk server PHP bawaan (php -S) saat dipasang sebagai add-on.
 * Folder data/ dan bin/ serta berkas tersembunyi tidak boleh dibuka dari web.
 */
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (preg_match('#^/(data|bin)(/|$)#', $path) || preg_match('#/\.#', $path) || preg_match('#\.(db|json|lock|bak|sh)$#i', $path)) {
    http_response_code(403);
    echo 'Forbidden';
    return true;
}
$file = __DIR__ . $path;
if ($path !== '/' && is_file($file) && !preg_match('#\.php$#', $path)) {
    return false; // berkas statis
}
// Hanya index.php yang dijalankan
$_SERVER['SCRIPT_NAME'] = '/index.php';
require __DIR__ . '/index.php';
