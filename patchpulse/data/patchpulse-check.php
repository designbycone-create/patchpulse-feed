<?php
/**
 * PatchPulse check file
 * ---------------------
 * Upload this ONE file to the main folder of your website (the same folder
 * that holds index.php - usually called public_html or www).
 *
 * What it does: tells YOUR PatchPulse app (and nobody else) which PHP
 * version your website runs, so PatchPulse can warn you about PHP flaws
 * even when your host hides the version.
 *
 * Safety: it only answers when the request carries your secret key, it
 * shares nothing except the PHP version and two PHP settings, it never
 * changes anything, and it has no inputs an attacker could abuse.
 * Delete it any time to stop.
 */

$PATCHPULSE_KEY = '__PATCHPULSE_KEY__';

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');

$given = isset($_SERVER['HTTP_X_PATCHPULSE_TOKEN']) ? (string) $_SERVER['HTTP_X_PATCHPULSE_TOKEN'] : '';

if ($PATCHPULSE_KEY === '' || strpos($PATCHPULSE_KEY, '__') === 0) {
    http_response_code(404);
    exit;
}
if ($given === '') {
    http_response_code(404); // look like the file isn't here
    exit;
}
if (!hash_equals($PATCHPULSE_KEY, $given)) {
    http_response_code(403);
    echo '{"error":"wrong key"}';
    exit;
}

echo json_encode(array(
    'app' => 'patchpulse',
    'v' => 1,
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'upload_progress' => (bool) ini_get('session.upload_progress.enabled'),
));
