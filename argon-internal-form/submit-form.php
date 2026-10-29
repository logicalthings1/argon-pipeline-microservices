<?php
// CRITICAL: Load Composer's autoloader so PHP can find PHPMailer
require __DIR__ . '/vendor/autoload.php';

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://argonpipeline.com';
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
        // [LOG TRIGGER 1]: Track direct URL bypass attempts
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Invalid Origin attempted - ' . ($current_origin ?: 'No Origin')]);
        file_put_contents('php://stderr', $logData . "\n");
        
        header('Content-Type: application/json');
        echo json_encode([
            "status" => "error", 
            "code" => "UNAUTHORIZED_ORIGIN", 
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

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim($data['fax_number']) : '';
if (!empty($honeypot)) {
    // [LOG TRIGGER 2]: Track when a bot falls into the trap
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot. (Hidden fax_number field filled)']);
    file_put_contents('php://stderr', $logData . "\n");
    
    // Fake a successful response and kill the script instantly
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "message" => "Message sent securely."]);
    exit;
}

// =========================================================================
// 3.1 CAPTURE METADATA (IP & USER AGENT)
// =========================================================================
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    // Cloud Run passes client IP as the first IP in a comma-separated list
    $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $userIp = trim($ipList[0]);
} else {
    $userIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

$userIp    = htmlspecialchars($userIp, ENT_QUOTES, 'UTF-8');
$userAgent = htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8');

// =========================================================================
// 4. TURNSTILE VERIFICATION
// =========================================================================
$turnstileResponse = $data['cf-turnstile-response'] ?? '';
$turnstileSecret   = getenv('TURNSTILE_SECRET');

if (empty($turnstileResponse)) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "Please complete the security check."]);
    exit;
}

// Verify the token with Cloudflare
$verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
$verifyData = [
    'secret'   => $turnstileSecret,
    'response' => $turnstileResponse,
    'remoteip' => $userIp // Pass the true client IP
];

$options = [
    'http' => [
        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
        'method'  => 'POST',
        'content' => http_build_query($verifyData)
    ]
];
$context  = stream_context_create($options);
$verifyResult = file_get_contents($verifyUrl, false, $context);
$cfData = json_decode($verifyResult, true);

if (!$cfData['success']) {
	// [LOG TRIGGER 3]: Track when Cloudflare rejects the token
	$logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Turnstile validation failed.']);
	file_put_contents('php://stderr', $logData . "\n");

	header('Content-Type: application/json');
	echo json_encode(["status" => "error", "message" => "Security verification failed. Please try again."]);
	exit;
}

// =========================================================================
// 5. DATA SANITIZATION & VALIDATION
// =========================================================================
$firstName = isset($data['first_name']) ? trim($data['first_name']) : '';
$lastName  = isset($data['last_name'])  ? trim($data['last_name']) : '';
$email     = isset($data['email'])      ? filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL) : false;
$url       = isset($data['url'])        ? trim($data['url']) : '';
$service   = isset($data['service'])    ? trim($data['service']) : '';
$message   = isset($data['message'])    ? trim($data['message']) : '';

if (empty($firstName) || empty($lastName) || empty($url) || empty($service) || empty($message) || !$email) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "Invalid form data provided. Please check your inputs."]);
    exit;
}

$firstName = htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8');
$lastName  = htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8');
$url       = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
$service   = htmlspecialchars($service, ENT_QUOTES, 'UTF-8');
$message   = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// =========================================================================
// 6. GOOGLE WORKSPACE / PHPMAILER PROCESSING
// =========================================================================
$smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpUser = getenv('SMTP_USER') ?: 'info@argonpipeline.com';
$smtpPass = getenv('SMTP_PASS');
$smtpPort = getenv('SMTP_PORT') ?: 465;

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
    $emailBody .= "Message:\n" . $message . "\n";
    $emailBody .= "----------------------------------------\n\n";
	$emailBody .= "IP Address: https://www.ip2location.com/demo/" . $userIp . "\n";
    $emailBody .= "User Agent: " . $userAgent . "\n";
    $emailBody .= "\n";

	$mail->Body = $emailBody;
    $mail->send();

// =========================================================================
// 7. SUCCESS RESPONSE
// =========================================================================
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "message" => "Message sent securely."]);
    exit;

} catch (Exception $e) {
    // 1. Safely extract error
    $detailedError = (isset($mail) && !empty($mail->ErrorInfo)) ? $mail->ErrorInfo : $e->getMessage();
    $errorMessage = 'MAILER ERROR: ' . $detailedError;
    
    // 2. Log to stderr for Google Cloud Logging
    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");
    
    // 3. Send Discord Webhook Alert using robust cURL
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
        
        // If Discord rejects the message, log the exact reason to Cloud Run
        if ($httpCode < 200 || $httpCode >= 300) {
            $discordLog = json_encode(['severity' => 'WARNING', 'message' => 'Discord Webhook Failed. HTTP: ' . $httpCode . ' Response: ' . $discordResponse]);
            file_put_contents('php://stderr', $discordLog . "\n");
        }
    } else {
        // Log if ALERT_WEBHOOK_URL is missing in Cloud Run env vars
        $missingEnvLog = json_encode(['severity' => 'WARNING', 'message' => 'Discord Webhook skipped: ALERT_WEBHOOK_URL environment variable is empty or not set.']);
        file_put_contents('php://stderr', $missingEnvLog . "\n");
    }

    // 4. Return a sanitized JSON response to the front-end
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}