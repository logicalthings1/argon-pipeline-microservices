<?php
// CRITICAL: Load Composer's autoloader so PHP can find PHPMailer
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.argonpipeline.com;https://argonpipeline.com;https://argon.argonpipeline.com';
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

if (isset($_SERVER['HTTP_HOST'])) {
    $allowed_origins[] = 'https://' .$_SERVER['HTTP_HOST'];
}
$allowed_origins = array_values(array_unique(array_filter($allowed_origins)));

$current_origin =$_SERVER['HTTP_ORIGIN'] ?? '';

// If the request comes from an unknown domain, kill it immediately.
if (empty($current_origin) || !in_array($current_origin,$allowed_origins)) {
    if (empty($current_origin) && isset($_SERVER['HTTP_HOST'])) {
        $current_origin = 'https://' .$_SERVER['HTTP_HOST'];
    } else {
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Invalid Origin attempted - ' . ($current_origin ?: 'No Origin')]);
        file_put_contents('php://stderr', $logData . "\n");
        
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            "status"  => "error", 
            "success" => false,
            "code"    => "UNAUTHORIZED_ORIGIN", 
            "message" => "Security verification failed. Invalid Origin."
        ]);
        exit;
    }
}

// =========================================================================
// 2. SET STRICT API HEADERS
// =========================================================================
header("Access-Control-Allow-Origin: " . $current_origin);
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// =========================================================================
// 3. READ & SANITIZE THE SECURE JSON PAYLOAD
// =========================================================================
$json_payload = file_get_contents('php://input');
$data = json_decode($json_payload, true);
if (!$data && !empty($_POST)) {
    $data =$_POST;
}

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim($data['fax_number']) : '';
if (!empty($honeypot)) {$logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot. (Hidden fax_number field filled)']);
    file_put_contents('php://stderr', $logData . "\n");
    
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;
}

// =========================================================================
// 3.1 CAPTURE METADATA (IP & USER AGENT)
// =========================================================================
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipList = explode(',',$_SERVER['HTTP_X_FORWARDED_FOR']);
    $userIp = trim($ipList[0]);
} else {
    $userIp =$_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

$userAgent =$_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$userIp    = strip_tags($userIp);
$userAgent = strip_tags($userAgent);

// =========================================================================
// 4. TURNSTILE VERIFICATION
// =========================================================================
$turnstileResponse = $data['cf-turnstile-response'] ?? '';$turnstileSecret   = getenv('TURNSTILE_SECRET');

if (empty($turnstileResponse)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Please complete the security check."]);
    exit;
}

// Verify the token with Cloudflare
$verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';$verifyData = [
    'secret'   => $turnstileSecret,
    'response' => $turnstileResponse,
    'remoteip' => $userIp
];

$options = [
    'http' => [
        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
        'method'  => 'POST',
        'content' => http_build_query($verifyData)
    ]
];
$context      = stream_context_create($options);$verifyResult = file_get_contents($verifyUrl, false,$context);
$cfData       = json_decode($verifyResult, true);

if (empty($cfData['success'])) {$logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Turnstile validation failed.']);
    file_put_contents('php://stderr', $logData . "\n");

    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Security verification failed. Please try again."]);
    exit;
}

// =========================================================================
// 5. DATA SANITIZATION & VALIDATION (WCAG 2.1 AA FIELD-LEVEL ERRORS)
// =========================================================================
$firstName    = isset($data['first_name']) ? trim($data['first_name']) : '';
$lastName     = isset($data['last_name']) ? trim($data['last_name']) : '';$email        = isset($data['email']) ? filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL) : false;
$url          = isset($data['url']) ? trim($data['url']) : '';$service      = isset($data['service']) ? trim($data['service']) : '';
$specifyOther = isset($data['specify_other']) ? trim($data['specify_other']) : '';$message      =