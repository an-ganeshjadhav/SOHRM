<?php

/**
 * SOHRM Configuration
 */

// ───────────────────────────── Auto-detect Domain ─────────────────
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
$origin = $scheme . '://' . $host;

// ───────────────────────────── OrangeHRM Local URLs ─────────────────────
define('OHRM_BASE_URL', $origin . '/orangehrm/orangehrm/web/index.php');
define('OHRM_WEB_URL',  $origin . '/orangehrm/orangehrm/web');

// ───────────────────────────── SOHRM Live URLs ─────────────────────
// define('OHRM_BASE_URL', $origin . '/web/index.php');
// define('OHRM_WEB_URL',  $origin . '/web');
// define('OAUTH_REDIRECT_URI',  $origin . '/index.php');


// ───────────────────────────── OAuth2 Client ──────────────────────
define('OAUTH_CLIENT_ID',     'e02728981b5553a28649f8ff3d98431b');       // Register via Admin > OAuth Clients
define('OAUTH_CLIENT_SECRET', 'i79D+RiOfsErbvDETYKpJ/zW1FIwPauXeJEZEqZNwkw=');
define('OAUTH_REDIRECT_URI',  $origin . '/SOHRM/index.php');
