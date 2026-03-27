<?php

/**
 * SOHRM - Employee Attendance Report (API-based)
 *
 * Uses OrangeHRM REST APIs with OAuth2 Authorization Code flow:
 *   - /api/v2/attendance/employees/daily-hours-compliance
 *   - /api/v2/pim/employees
 *
 * Standalone login — authenticates against OrangeHRM entirely via server-side cURL.
 * Only Admin users can access.
 */

session_start();

// Prevent browser from caching authenticated pages (fixes back-button form resubmission)
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

// ───────────────────────────── Config ─────────────────────────────
require_once __DIR__ . '/config.php';

$orhrmBaseUrl = OHRM_BASE_URL;
$orhrmWebUrl  = OHRM_WEB_URL;
$clientId     = OAUTH_CLIENT_ID;
$clientSecret = OAUTH_CLIENT_SECRET;
$redirectUri  = OAUTH_REDIRECT_URI;

$loginError = '';

// ───────────────────────────── Server-side OAuth2 Login ───────────

/**
 * Perform the full OrangeHRM OAuth2 flow server-side via cURL:
 *   1. GET  /auth/login           → extract CSRF token + session cookie
 *   2. POST /auth/validate        → authenticate
 *   3. GET  /oauth2/authorize     → initiate authorization
 *   4. GET  /oauth2/authorize/consent?authorized=true → approve
 *   5. POST /oauth2/token         → exchange code for access token
 */
function serverSideOAuth2Login(string $username, string $password, string $baseUrl, string $webUrl, string $clientId, string $clientSecret, string $redirectUri): array
{
    // Use a single cURL handle to keep cookies in memory across all steps
    // (avoids PHP 8.x bug where curl_close doesn't flush session cookies to jar file)
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_COOKIEFILE     => '', // enable in-memory cookie engine
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => 15,
    ]);

    try {
        // ── Step 1: GET login page to obtain CSRF token and session cookie ──
        curl_setopt_array($ch, [
            CURLOPT_URL            => $baseUrl . '/auth/login',
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
        ]);
        $loginPage = curl_exec($ch);
        $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($httpCode !== 200 || !$loginPage) {
            return ['error' => 'Unable to connect to OrangeHRM. Please try again later.'];
        }

        // Extract CSRF token — OrangeHRM uses Vue prop :token="&quot;...&quot;" (may span multiple lines)
        if (
            !preg_match('/:token=["\']&quot;([\s\S]*?)&quot;["\']/', $loginPage, $m)
            && !preg_match('/name=["\']_token["\'].*?value=["\']([^"\']+)["\']/', $loginPage, $m)
        ) {
            return ['error' => 'Unable to retrieve login token from OrangeHRM.'];
        }
        $csrfToken = preg_replace('/\s+/', '', $m[1]);

        // ── Step 2: POST credentials to /auth/validate ──
        curl_setopt_array($ch, [
            CURLOPT_URL            => $baseUrl . '/auth/validate',
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'username' => $username,
                'password' => $password,
                '_token'   => $csrfToken,
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        // OrangeHRM redirects to /dashboard on success, back to /auth/login on failure
        if ($httpCode !== 302) {
            return ['error' => 'Invalid username or password.'];
        }

        // Check redirect location — login failure redirects back to /auth/login
        if (preg_match('/^Location:\s*(.+)$/mi', $response, $locMatch)) {
            $redirectTo = trim($locMatch[1]);
            if (strpos($redirectTo, '/auth/login') !== false) {
                return ['error' => 'Invalid username or password.'];
            }
            // Handle password enforcement redirect (new users with weak passwords)
            if (
                strpos($redirectTo, 'changeWeakPassword') !== false
                || strpos($redirectTo, 'resetWeakPassword') !== false
            ) {
                return ['error' => 'Your password does not meet the strength requirements. Please change your password in OrangeHRM first, then try again.'];
            }
        }

        // ── Step 3: GET /oauth2/authorize (with authenticated session) ──
        $authorizeParams = http_build_query([
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'state'         => bin2hex(random_bytes(16)),
        ]);
        $authorizeUrl = $webUrl . '/oauth2/authorize?' . $authorizeParams;

        curl_setopt_array($ch, [
            CURLOPT_URL            => $authorizeUrl,
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        // ── Step 4: Approve the consent (auto-approve) ──
        $consentUrl = $webUrl . '/oauth2/authorize/consent?' . $authorizeParams . '&authorized=true';

        curl_setopt_array($ch, [
            CURLOPT_URL            => $consentUrl,
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
        ]);
        $response   = curl_exec($ch);
        $httpCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $redirectUrl = '';
        if (preg_match('/^Location:\s*(.+)$/mi', $response, $locMatch)) {
            $redirectUrl = trim($locMatch[1]);
        }

        if ($httpCode !== 302 || !$redirectUrl) {
            return ['error' => 'OAuth authorization failed. Please try again.'];
        }

        // Extract authorization code from redirect URL
        $parsedUrl = parse_url($redirectUrl);
        parse_str($parsedUrl['query'] ?? '', $queryParams);

        if (empty($queryParams['code'])) {
            $errMsg = $queryParams['error_description'] ?? ($queryParams['error'] ?? 'Authorization denied.');
            return ['error' => $errMsg];
        }

        // ── Step 5: Exchange authorization code for access token ──
        curl_setopt_array($ch, [
            CURLOPT_URL            => $webUrl . '/oauth2/token',
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'grant_type'    => 'authorization_code',
                'code'          => $queryParams['code'],
                'client_id'     => $clientId,
                'client_secret' => $clientSecret,
                'redirect_uri'  => $redirectUri,
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $tokenResponse = curl_exec($ch);
        $httpCode      = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($httpCode !== 200) {
            return ['error' => 'Failed to obtain access token. Please try again.'];
        }

        $tokenData = json_decode($tokenResponse, true);
        if (empty($tokenData['access_token'])) {
            return ['error' => 'Invalid token response from OrangeHRM.'];
        }

        // ── Step 6: Verify Admin role ──
        // Use a fresh cURL handle (no session cookies) to verify the Bearer token works independently
        $adminCh = curl_init($baseUrl . '/api/v2/admin/users?limit=1');
        curl_setopt_array($adminCh, [
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_HTTPHEADER     => [
                'Authorization: Bearer ' . $tokenData['access_token'],
                'Accept: application/json',
            ],
        ]);
        curl_exec($adminCh);
        $adminCheck = curl_getinfo($adminCh, CURLINFO_HTTP_CODE);
        curl_close($adminCh);

        if ($adminCheck === 403 || $adminCheck === 401) {
            return ['error' => 'Access Denied. Only users with the Admin role can access SOHRM.'];
        }

        return [
            'access_token'  => $tokenData['access_token'],
            'refresh_token' => $tokenData['refresh_token'] ?? '',
            'expires_in'    => $tokenData['expires_in'] ?? 1800,
        ];
    } finally {
        curl_close($ch);
    }
}

// Handle login form submission (PRG pattern — always redirect after POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sohrm_login'])) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        $_SESSION['login_error'] = 'Please enter both username and password.';
    } else {
        $result = serverSideOAuth2Login($username, $password, $orhrmBaseUrl, $orhrmWebUrl, $clientId, $clientSecret, $redirectUri);

        if (isset($result['error'])) {
            $_SESSION['login_error'] = $result['error'];
        } else {
            $_SESSION['access_token']  = $result['access_token'];
            $_SESSION['refresh_token'] = $result['refresh_token'];
            $_SESSION['token_expiry']  = time() + $result['expires_in'];
        }
    }
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

// Retrieve and clear any login error from session (flash message)
if (!empty($_SESSION['login_error'])) {
    $loginError = $_SESSION['login_error'];
    unset($_SESSION['login_error']);
}

// Handle token refresh
if (isset($_SESSION['access_token'], $_SESSION['token_expiry']) && time() >= $_SESSION['token_expiry'] && !empty($_SESSION['refresh_token'])) {
    $tokenUrl = $orhrmWebUrl . '/oauth2/token';
    $postData = [
        'grant_type'    => 'refresh_token',
        'refresh_token' => $_SESSION['refresh_token'],
        'client_id'     => $clientId,
        'client_secret' => $clientSecret,
    ];

    $ch = curl_init($tokenUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($postData),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 15,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200) {
        $tokenData = json_decode($response, true);
        $_SESSION['access_token']  = $tokenData['access_token'];
        $_SESSION['refresh_token'] = $tokenData['refresh_token'] ?? '';
        $_SESSION['token_expiry']  = time() + ($tokenData['expires_in'] ?? 1800);
    } else {
        unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['token_expiry']);
    }
}

// Handle logout — fully destroy session
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

// Check if authenticated
$isAuthenticated = !empty($_SESSION['access_token']) && time() < ($_SESSION['token_expiry'] ?? 0);

// ───────────────────────────── API Helper ─────────────────────────
function apiGet(string $url, string $token): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $token,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 30,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200) {
        return json_decode($response, true);
    }
    if ($httpCode === 401 || $httpCode === 403) {
        return ['_error' => $httpCode, '_message' => 'Unauthorized or forbidden. Only Admin can access.'];
    }
    return ['_error' => $httpCode, '_message' => 'API request failed'];
}

// ───────────────────────────── Data Fetch ─────────────────────────
$empNumber  = isset($_GET['emp_number']) ? (int)$_GET['emp_number'] : 0;
$month      = isset($_GET['month']) ? (int)$_GET['month'] : (int)date('m');
$year       = isset($_GET['year']) ? (int)$_GET['year'] : (int)date('Y');
$filterDate = isset($_GET['date']) && $_GET['date'] !== '' ? $_GET['date'] : '';
$viewMode   = 'month';
$apiError   = '';

if ($month < 1 || $month > 12) $month = (int)date('m');
if ($year < 2000 || $year > 2100) $year = (int)date('Y');

if ($filterDate !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $filterDate) && strtotime($filterDate)) {
    $viewMode   = 'date';
    $fromDate   = $filterDate;
    $toDate     = $filterDate;
    $monthLabel = date('l, d F Y', strtotime($filterDate));
    $month      = (int)date('m', strtotime($filterDate));
    $year       = (int)date('Y', strtotime($filterDate));
} else {
    $fromDate   = sprintf('%04d-%02d-01', $year, $month);
    $lastDay    = (int)date('t', mktime(0, 0, 0, $month, 1, $year));
    $toDate     = sprintf('%04d-%02d-%02d', $year, $month, $lastDay);
    $monthLabel = date('F Y', mktime(0, 0, 0, $month, 1, $year));
}

// Future date check
$today        = date('Y-m-d');
$isFutureDate = ($fromDate > $today);

$employees      = [];
$attendanceData = [];
$employeeName   = '';
$presentDays    = 0;
$absentDays     = 0;

if ($isAuthenticated) {
    $token = $_SESSION['access_token'];

    // Fetch employee list via API
    $empApiUrl  = $orhrmBaseUrl . '/api/v2/pim/employees?limit=0&includeEmployees=currentAndPast';
    $empResult  = apiGet($empApiUrl, $token);

    if (isset($empResult['_error'])) {
        $apiError = $empResult['_message'];
        if ($empResult['_error'] == 401) {
            unset($_SESSION['access_token']);
            $isAuthenticated = false;
        }
    } elseif (isset($empResult['data'])) {
        foreach ($empResult['data'] as $emp) {
            $employees[] = [
                'emp_number'    => $emp['empNumber'],
                'employee_id'   => $emp['employeeId'] ?? '',
                'emp_firstname' => $emp['firstName'],
                'emp_lastname'  => $emp['lastName'],
            ];
        }
        // Sort by last name
        usort($employees, fn($a, $b) => strcasecmp($a['emp_lastname'], $b['emp_lastname']));
    }

    // Fetch attendance report via Daily 9Hr API
    if ($empNumber > 0 && !$isFutureDate && $isAuthenticated && !$apiError) {
        $reportUrl = $orhrmBaseUrl . '/api/v2/attendance/employees/daily-hours-compliance'
            . '?fromDate=' . urlencode($fromDate)
            . '&toDate=' . urlencode($toDate)
            . '&empNumber=' . $empNumber
            . '&limit=0';

        $reportResult = apiGet($reportUrl, $token);

        if (isset($reportResult['_error'])) {
            $apiError = $reportResult['_message'];
        } elseif (isset($reportResult['data'])) {
            // Get employee name from first record or employee list
            foreach ($employees as $emp) {
                if ((int)$emp['emp_number'] === $empNumber) {
                    $employeeName = htmlspecialchars($emp['emp_firstname'] . ' ' . $emp['emp_lastname'] . ' (' . $emp['employee_id'] . ')');
                    break;
                }
            }

            foreach ($reportResult['data'] as $record) {
                $isPresent = !empty($record['completed9Hours']);
                $hours   = (int)($record['duration']['hours'] ?? 0);
                $minutes = (int)($record['duration']['minutes'] ?? 0);
                $label   = $record['duration']['label'] ?? '0.00';

                if ($isPresent) $presentDays++;
                else $absentDays++;

                $attendanceData[] = [
                    'date'      => $record['date'],
                    'day_name'  => date('l', strtotime($record['date'])),
                    'hours'     => $hours,
                    'minutes'   => $minutes,
                    'total_hrs' => $label,
                    'status'    => $isPresent ? 'Present' : 'Absent',
                ];
            }

            // If month view, fill in missing working days as Absent
            if ($viewMode === 'month') {
                $existingDates = array_column($attendanceData, 'date');
                $lastDay = (int)date('t', mktime(0, 0, 0, $month, 1, $year));
                for ($day = 1; $day <= $lastDay; $day++) {
                    $dateStr = sprintf('%04d-%02d-%02d', $year, $month, $day);
                    $dayOfWeek = (int)date('N', strtotime($dateStr));
                    if ($dayOfWeek >= 6) continue; // skip weekends
                    if ($dateStr > $today) continue; // skip future days
                    if (in_array($dateStr, $existingDates)) continue;

                    $absentDays++;
                    $attendanceData[] = [
                        'date'      => $dateStr,
                        'day_name'  => date('l', strtotime($dateStr)),
                        'hours'     => 0,
                        'minutes'   => 0,
                        'total_hrs' => '0.00',
                        'status'    => 'Absent',
                    ];
                }
                // Sort by date
                usort($attendanceData, fn($a, $b) => strcmp($a['date'], $b['date']));
            }

            // For date view with no data, add a single absent row
            if ($viewMode === 'date' && empty($attendanceData)) {
                $dayOfWeek = (int)date('N', strtotime($filterDate));
                $isWeekend = ($dayOfWeek >= 6);
                if (!$isWeekend) $absentDays++;
                $attendanceData[] = [
                    'date'      => $filterDate,
                    'day_name'  => date('l', strtotime($filterDate)),
                    'hours'     => 0,
                    'minutes'   => 0,
                    'total_hrs' => '0.00',
                    'status'    => $isWeekend ? 'Weekend' : 'Absent',
                ];
            }
        }
    } elseif ($empNumber > 0 && $isFutureDate) {
        foreach ($employees as $emp) {
            if ((int)$emp['emp_number'] === $empNumber) {
                $employeeName = htmlspecialchars($emp['emp_firstname'] . ' ' . $emp['emp_lastname'] . ' (' . $emp['employee_id'] . ')');
                break;
            }
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOHRM - Employee Attendance Report (API)</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f4f6f9;
            color: #333;
        }

        .container {
            max-width: 1000px;
            margin: 30px auto;
            padding: 0 20px;
        }

        h1 {
            color: #e65100;
            margin-bottom: 5px;
            font-size: 24px;
        }

        .subtitle {
            color: #888;
            font-size: 13px;
            margin-bottom: 20px;
        }

        .auth-box {
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .auth-box p {
            margin-bottom: 15px;
            color: #666;
        }

        .btn-login {
            display: inline-block;
            padding: 12px 30px;
            background: #e65100;
            color: #fff;
            text-decoration: none;
            border-radius: 4px;
            font-size: 15px;
            font-weight: 600;
        }

        .btn-login:hover {
            background: #bf360c;
        }

        .btn-logout {
            display: inline-block;
            padding: 6px 16px;
            background: #757575;
            color: #fff;
            text-decoration: none;
            border-radius: 4px;
            font-size: 12px;
            margin-left: 10px;
        }

        .btn-logout:hover {
            background: #424242;
        }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .badge-api {
            background: #1565c0;
            color: #fff;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 3px;
            vertical-align: middle;
            margin-left: 8px;
        }

        .filter-form {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            align-items: flex-end;
            flex-wrap: wrap;
        }

        .filter-form label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 5px;
            color: #555;
        }

        .filter-form select,
        .filter-form input {
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
            min-width: 160px;
        }

        .filter-form button {
            padding: 9px 24px;
            background: #e65100;
            color: #fff;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
        }

        .filter-form button:hover {
            background: #bf360c;
        }

        .separator {
            font-weight: 700;
            color: #e65100;
            font-size: 14px;
            align-self: center;
            padding-bottom: 2px;
        }

        .summary {
            background: #fff;
            padding: 16px 20px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }

        .summary-item {
            font-size: 15px;
        }

        .summary-item strong {
            color: #e65100;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #fff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        }

        th {
            background: #e65100;
            color: #fff;
            padding: 12px 14px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
        }

        td {
            padding: 10px 14px;
            border-bottom: 1px solid #eee;
            font-size: 14px;
        }

        tr:hover td {
            background: #fff8e1;
        }

        .status-present {
            color: #2e7d32;
            font-weight: 600;
        }

        .status-absent {
            color: #c62828;
            font-weight: 600;
        }

        .status-weekend {
            color: #6a6a6a;
            font-weight: 600;
            font-style: italic;
        }

        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 16px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        }

        .error-box {
            background: #ffebee;
            color: #c62828;
            padding: 14px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>

<body>
    <div class="container">

        <?php if (!$isAuthenticated): ?>
            <!-- ───────── Login Screen ───────── -->
            <h1>Employee Attendance Report <span class="badge-api">via API</span></h1>
            <p class="subtitle">Sign in with your OrangeHRM Admin credentials</p>

            <?php if ($loginError): ?>
                <div class="error-box" style="text-align:center;">
                    <?= htmlspecialchars($loginError) ?>
                </div>
            <?php endif; ?>

            <div class="auth-box">
                <p>Sign in with your <strong>OrangeHRM Admin</strong> account to access attendance reports.</p>
                <form method="POST" action="" style="display:inline-block; text-align:left; width:100%; max-width:320px; margin-top:10px;">
                    <div style="margin-bottom:14px;">
                        <label for="username" style="display:block; font-size:13px; font-weight:600; color:#555; margin-bottom:5px;">Username</label>
                        <input type="text" id="username" name="username" required autofocus
                            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                            style="width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:4px; font-size:14px;">
                    </div>
                    <div style="margin-bottom:18px;">
                        <label for="password" style="display:block; font-size:13px; font-weight:600; color:#555; margin-bottom:5px;">Password</label>
                        <input type="password" id="password" name="password" required
                            style="width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:4px; font-size:14px;">
                    </div>
                    <button type="submit" name="sohrm_login" value="1" class="btn-login" style="width:100%; border:none; cursor:pointer; text-align:center;">Sign In</button>
                </form>
                <p style="font-size:12px; color:#999; margin-top:15px;">Only Admin users can access this application.</p>
            </div>

        <?php else: ?>
            <!-- ───────── Authenticated View ───────── -->
            <div class="topbar">
                <div>
                    <h1>Employee Attendance Report <span class="badge-api">via API</span></h1>
                    <p class="subtitle">Data from <code>/api/v2/attendance/employees/daily-hours-compliance</code></p>
                </div>
                <a href="?logout=1" class="btn-logout">Sign Out</a>
            </div>

            <?php if ($apiError): ?>
                <div class="error-box"><?= htmlspecialchars($apiError) ?></div>
            <?php endif; ?>

            <form class="filter-form" method="GET" action="">
                <div>
                    <label for="emp_number">Employee</label>
                    <select name="emp_number" id="emp_number" required>
                        <option value="">-- Select Employee --</option>
                        <?php foreach ($employees as $emp): ?>
                            <option value="<?= (int)$emp['emp_number'] ?>"
                                <?= $empNumber === (int)$emp['emp_number'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($emp['emp_firstname'] . ' ' . $emp['emp_lastname'] . ' (' . $emp['employee_id'] . ')') ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="month">Month</label>
                    <select name="month" id="month">
                        <?php for ($m = 1; $m <= 12; $m++): ?>
                            <option value="<?= $m ?>" <?= $month === $m ? 'selected' : '' ?>>
                                <?= date('F', mktime(0, 0, 0, $m, 1)) ?>
                            </option>
                        <?php endfor; ?>
                    </select>
                </div>
                <div>
                    <label for="year">Year</label>
                    <select name="year" id="year">
                        <?php for ($y = (int)date('Y') - 2; $y <= (int)date('Y') + 1; $y++): ?>
                            <option value="<?= $y ?>" <?= $year === $y ? 'selected' : '' ?>><?= $y ?></option>
                        <?php endfor; ?>
                    </select>
                </div>
                <div class="separator">OR</div>
                <div>
                    <label for="date">Specific Date</label>
                    <input type="date" name="date" id="date" value="<?= htmlspecialchars($filterDate) ?>">
                </div>
                <div>
                    <button type="submit">View Report</button>
                </div>
            </form>

            <?php if ($empNumber > 0 && $isFutureDate): ?>
                <div class="summary">
                    <div class="summary-item"><strong>Employee:</strong> <?= $employeeName ?></div>
                    <div class="summary-item"><strong><?= $viewMode === 'date' ? 'Date' : 'Month' ?>:</strong> <?= htmlspecialchars($monthLabel) ?></div>
                </div>
                <div class="no-data">No data available — the selected <?= $viewMode === 'date' ? 'date' : 'month' ?> is in the future.</div>

            <?php elseif ($empNumber > 0 && !$apiError): ?>
                <div class="summary">
                    <div class="summary-item"><strong>Employee:</strong> <?= $employeeName ?></div>
                    <div class="summary-item"><strong><?= $viewMode === 'date' ? 'Date' : 'Month' ?>:</strong> <?= htmlspecialchars($monthLabel) ?></div>
                    <div class="summary-item"><strong>Working Days:</strong> <?= $presentDays + $absentDays ?></div>
                    <div class="summary-item"><strong>Present (&ge;9hrs):</strong> <span class="status-present"><?= $presentDays ?></span></div>
                    <div class="summary-item"><strong>Absent (&lt;9hrs):</strong> <span class="status-absent"><?= $absentDays ?></span></div>
                </div>

                <?php if (count($attendanceData) > 0): ?>
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Date</th>
                                <th>Day</th>
                                <th>Hours Worked</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($attendanceData as $i => $row): ?>
                                <tr>
                                    <td><?= $i + 1 ?></td>
                                    <td><?= htmlspecialchars($row['date']) ?></td>
                                    <td><?= htmlspecialchars($row['day_name']) ?></td>
                                    <td><?= htmlspecialchars($row['total_hrs']) ?> hrs (<?= $row['hours'] ?>h <?= $row['minutes'] ?>m)</td>
                                    <td class="<?= $row['status'] === 'Present' ? 'status-present' : ($row['status'] === 'Weekend' ? 'status-weekend' : 'status-absent') ?>">
                                        <?= $row['status'] ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="no-data">No working days found for this <?= $viewMode === 'date' ? 'date' : 'month' ?>.</div>
                <?php endif; ?>

            <?php elseif (!$apiError): ?>
                <div class="no-data">Select an employee and month/date to view attendance report.</div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var dateEl = document.getElementById('date');
            var monthEl = document.getElementById('month');
            var yearEl = document.getElementById('year');
            if (!dateEl || !monthEl || !yearEl) return;

            dateEl.addEventListener('change', function() {
                monthEl.disabled = !!this.value;
                yearEl.disabled = !!this.value;
            });
            monthEl.addEventListener('change', function() {
                dateEl.value = '';
                monthEl.disabled = false;
                yearEl.disabled = false;
            });
            yearEl.addEventListener('change', function() {
                dateEl.value = '';
                monthEl.disabled = false;
                yearEl.disabled = false;
            });
            if (dateEl.value) {
                monthEl.disabled = true;
                yearEl.disabled = true;
            }
        });
    </script>
</body>

</html>