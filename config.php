<?php

/**
 * SOHRM Configuration
 */

// ───────────────────────────── OrangeHRM Internal URLs ─────────────────
// These are used for server-to-server cURL communication.
// Always use localhost since SOHRM runs on the same server as OrangeHRM.
// Do NOT auto-detect from HTTP_HOST — that changes per client machine
// and causes OAuth redirect_uri mismatch + API auth failures.
define('OHRM_BASE_URL', 'http://localhost/orangehrm/orangehrm/web/index.php');
define('OHRM_WEB_URL',  'http://localhost/orangehrm/orangehrm/web');

// ───────────────────────────── SOHRM Live URLs ─────────────────────
// define('OHRM_BASE_URL', 'http://localhost/web/index.php');
// define('OHRM_WEB_URL',  'http://localhost/web');
// define('OAUTH_REDIRECT_URI', 'http://localhost/index.php');


// ───────────────────────────── OAuth2 Client ──────────────────────
// OAUTH_REDIRECT_URI MUST exactly match the redirect URI registered
// in OrangeHRM Admin > OAuth Clients (use the same localhost URL).
define('OAUTH_CLIENT_ID',     'e02728981b5553a28649f8ff3d98431b');       // Register via Admin > OAuth Clients
define('OAUTH_CLIENT_SECRET', 'i79D+RiOfsErbvDETYKpJ/zW1FIwPauXeJEZEqZNwkw=');
define('OAUTH_REDIRECT_URI',  'http://localhost/SOHRM/index.php');
