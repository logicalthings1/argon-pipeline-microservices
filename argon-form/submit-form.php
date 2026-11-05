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
    $allowed_origins[] = 'https://' . $_SERVER['HTTP_HOST'];
}
$allowed_origins = array_values(array_unique(array_filter($allowed_origins)));

$current_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// If the request comes from an unknown domain, kill it immediately.
if (empty($current_origin) || !in_array($current_origin, $allowed_origins)) {
    if (empty($current_origin) && isset($_SERVER['HTTP_HOST'])) {
        $current_origin = 'https://' . $_SERVER['HTTP_HOST'];
    } else {
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Invalid Origin attempted - ' . ($current_origin ?: 'No Origin')]);
        file_put_contents('php://stderr', $logData . "\n");
        
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
    $data = $_POST;
}

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim($data['fax_number']) : '';
if (!empty($honeypot)) {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot. (Hidden fax_number field filled)']);
    file_put_contents('php://stderr', $logData . "\n");
    
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;
}

// =========================================================================
// 3.1 CAPTURE METADATA (IP & USER AGENT)
// =========================================================================
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $userIp = trim($ipList[0]);
} else {
    $userIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$userIp    = strip_tags($userIp);
$userAgent = strip_tags($userAgent);

// =========================================================================
// 4. TURNSTILE VERIFICATION
// =========================================================================
$turnstileResponse = $data['cf-turnstile-response'] ?? '';
$turnstileSecret   = getenv('TURNSTILE_SECRET');

if (empty($turnstileResponse)) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Please complete the security check."]);
    exit;
}

// Verify the token with Cloudflare
$verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
$verifyData = [
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
$context      = stream_context_create($options);
$verifyResult = file_get_contents($verifyUrl, false, $context);
$cfData       = json_decode($verifyResult, true);

if (!$cfData['success']) {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Turnstile validation failed.']);
    file_put_contents('php://stderr', $logData . "\n");

    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Security verification failed. Please try again."]);
    exit;
}

// =========================================================================
// 5. DATA SANITIZATION & VALIDATION
// =========================================================================
$firstName    = isset($data['first_name']) ? trim($data['first_name']) : '';
$lastName     = isset($data['last_name']) ? trim($data['last_name']) : '';
$email        = isset($data['email']) ? filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL) : false;
$url          = isset($data['url']) ? trim($data['url']) : '';
$service      = isset($data['service']) ? trim($data['service']) : '';
$specifyOther = isset($data['specify_other']) ? trim($data['specify_other']) : '';
$message      = isset($data['message']) ? trim($data['message']) : '';

if (empty($firstName) || empty($lastName) || empty($url) || empty($service) || empty($message) || !$email) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Invalid form data provided. Please check your inputs."]);
    exit;
}

$firstName    = strip_tags($firstName);
$lastName     = strip_tags($lastName);
$url          = strip_tags($url);
$service      = strip_tags($service);
$specifyOther = strip_tags($specifyOther);
$message      = strip_tags($message);

// =========================================================================
// 6. GOOGLE WORKSPACE / PHPMAILER PROCESSING
// =========================================================================
$smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpUser = getenv('SMTP_USER') ?: 'art@logicalthings.com';
$smtpPass = getenv('SMTP_PASS');
$smtpPort = (int)(getenv('SMTP_PORT') ?: 465);

try {
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    $mail->SMTPSecure = 'ssl';
    $mail->Port       = $smtpPort;

    $mail->setFrom($smtpUser, 'Argon Pipeline System'); 
    $mail->addAddress('art@logicalthings.com'); 
    $mail->addReplyTo($email, "$firstName $lastName");

    $mail->Subject = "New Argon Pipeline Inquiry from $firstName $lastName";

    $emailBody  = "You have received a new inquiry via the Argon Pipeline form:\n\n";
    $emailBody .= "----------------------------------------\n";
    $emailBody .= "First Name: " . $firstName . "\n";
    $emailBody .= "Last Name: " . $lastName . "\n";
    $emailBody .= "Email: " . $email . "\n";
    $emailBody .= "Website URL: " . $url . "\n";
    $emailBody .= "Office Suite: " . ucfirst($service) . "\n";
    if (!empty($specifyOther)) {
        $emailBody .= "Specified Other Suite: " . $specifyOther . "\n";
    }
    $emailBody .= "Message:\n" . $message . "\n";
    $emailBody .= "----------------------------------------\n\n";
    $emailBody .= "IP Address: https://www.ip2location.com/demo/" . $userIp . "\n";
    $emailBody .= "User Agent: " . $userAgent . "\n";

    $mail->Body = $emailBody;
    $mail->send();

// =========================================================================
// 7. SUCCESS RESPONSE
// =========================================================================
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;

} catch (\Exception $e) {
    $detailedError = (isset($mail) && !empty($mail->ErrorInfo)) ? $mail->ErrorInfo : $e->getMessage();
    $errorMessage = 'MAILER ERROR: ' . $detailedError;
    
    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");
    
    $webhookUrl = getenv('ALERT_WEBHOOK_URL');
    if (!empty($webhookUrl)) {
        $domain = $_SERVER['HTTP_HOST'] ?? 'Unknown Domain';
        $alertPayload = json_encode([
            "content" => "[ALERT] **Argon Pipeline Form Error**\n**Domain:** " . $domain . "\n**Error:** " . $errorMessage
        ]);
        
        $ch = curl_init($webhookUrl);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $alertPayload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        
        $discordResponse = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode < 200 || $httpCode >= 300) {
            $discordLog = json_encode(['severity' => 'WARNING', 'message' => 'Discord Webhook Failed. HTTP: ' . $httpCode . ' Response: ' . $discordResponse]);
            file_put_contents('php://stderr', $discordLog . "\n");
        }
    } else {
        $missingEnvLog = json_encode(['severity' => 'WARNING', 'message' => 'Discord Webhook skipped: ALERT_WEBHOOK_URL environment variable is empty or not set.']);
        file_put_contents('php://stderr', $missingEnvLog . "\n");
    }

    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}
