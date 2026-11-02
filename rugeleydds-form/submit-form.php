<?php
// CRITICAL: Load Composer's autoloader
require __DIR__ . '/vendor/autoload.php';

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
// 1.1 Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.rugeleydds.com';
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

if (isset($_SERVER['HTTP_HOST'])) {
    $allowed_origins[] = 'https://' . $_SERVER['HTTP_HOST'];
}
$allowed_origins = array_values(array_unique(array_filter($allowed_origins)));

$current_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// If the request comes from an unknown domain, kill it immediately.
if (empty($current_origin) || !in_array($current_origin, $allowed_origins)) {
    // Exception for the Cloud Run container running internal health checks
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

// Handle preflight requests from the browser instantly
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// =========================================================================
// 3. READ & SANITIZE THE SECURE JSON PAYLOAD
// =========================================================================
$json_payload = file_get_contents('php://input');
$data = json_decode($json_payload, true);

// Fallback if data was sent via standard x-www-form-urlencoded
if (!$data && !empty($_POST)) {
    $data = $_POST;
}

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

// --- CLOUDFLARE TURNSTILE VERIFICATION ---
$turnstileSecret = getenv('TURNSTILE_SECRET_KEY');
if (!empty($turnstileSecret)) {
    $token = $data['cf-turnstile-response'] ?? '';
    if (empty($token)) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Spam verification token missing.']);
        exit;
    }

    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret'   => $turnstileSecret,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
    ]));
    $verifyResponse = curl_exec($ch);
    curl_close($ch);

    $responseData = json_decode($verifyResponse, true);
    if (empty($responseData['success'])) {
        $logData = json_encode(['severity' => 'WARNING', 'message' => 'SECURITY BLOCK: Turnstile verification failed.']);
        file_put_contents('php://stderr', $logData . "\n");
        
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Bot challenge verification failed.']);
        exit;
    }
}

// --- DATA SANITIZATION & VALIDATION ---
$formType      = isset($data['form_type'])      ? trim($data['form_type'])      : 'contact';
$firstName     = isset($data['first_name'])     ? trim($data['first_name'])     : '';
$lastName      = isset($data['last_name'])      ? trim($data['last_name'])      : '';
$email         = isset($data['email'])          ? filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL) : false;
$phone         = isset($data['phone'])          ? trim($data['phone'])          : '';
$message       = isset($data['message'])        ? trim($data['message'])        : (isset($data['notes']) ? trim($data['notes']) : '');
$consent       = isset($data['consent'])        ? trim($data['consent'])        : '';

// Appointment Specifics
$preferredDate = isset($data['preferred_date']) ? trim($data['preferred_date']) : '';
$preferredTime = isset($data['preferred_time']) ? trim($data['preferred_time']) : '';
$patientType   = isset($data['patient_type'])   ? trim($data['patient_type'])   : '';

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
// 3.2 REQUIRED FIELDS CHECK
// =========================================================================
if (empty($firstName) || empty($lastName) || empty($phone) || empty($message) || !$email) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "Please complete all required fields and ensure your email is valid."]);
    exit;
}

// UPGRADED SANITIZATION (Replaced strip_tags for XSS protection)
$firstName     = htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8');
$lastName      = htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8');
$phone         = htmlspecialchars($phone, ENT_QUOTES, 'UTF-8');
$message       = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
$preferredDate = htmlspecialchars($preferredDate, ENT_QUOTES, 'UTF-8');
$preferredTime = htmlspecialchars($preferredTime, ENT_QUOTES, 'UTF-8');
$patientType   = htmlspecialchars($patientType, ENT_QUOTES, 'UTF-8');

// =========================================================================
// 4. MICROSOFT GRAPH API PROCESSING (OAuth 2.0)
// =========================================================================
$tenantId     = getenv('MS_TENANT_ID');
$clientId     = getenv('MS_CLIENT_ID');
$clientSecret = getenv('MS_CLIENT_SECRET');
$senderEmail  = getenv('MS_SENDER_EMAIL') ?: 'reception@rugeleydds.com';

// Construct Dynamic Email Body
if ($formType === 'appointment') {
    $emailSubject = "New Appointment Request from $firstName $lastName";
    $emailBody  = "You have received a secure appointment request:\n\n";
    $emailBody .= "Patient Status: " . ($patientType ?: 'Not Specified') . "\n";
    $emailBody .= "Name: " . $firstName . " " . $lastName . "\n";
    $emailBody .= "Email: " . $email . "\n";
    $emailBody .= "Phone: " . $phone . "\n";
    if (!empty($preferredDate)) $emailBody .= "Preferred Date: " . $preferredDate . "\n";
    if (!empty($preferredTime)) $emailBody .= "Preferred Time: " . $preferredTime . "\n";
} else {
    $emailSubject = "New website message from $firstName $lastName";
    $emailBody  = "You have received a secure website message:\n\n";
    $emailBody .= "Name: " . $firstName . " " . $lastName . "\n";
    $emailBody .= "Email: " . $email . "\n";
    $emailBody .= "Phone: " . $phone . "\n";
}

$emailBody .= "Message/Notes:\n" . $message . "\n\n";
$emailBody .= "----------------------------------------\n";
$emailBody .= "⚠️ HIPAA NOTICE: This message may contain Protected Health Information (PHI). To minimize the risk of inadvertently exposing PHI via unencrypted email, please delete the patient's original message before sending your reply.\n";
$emailBody .= "----------------------------------------\n\n";
$emailBody .= "Consent Given: " . ($consent ? 'Yes' : 'Not Recorded') . "\n";
$emailBody .= "IP Address: https://www.ip2location.com/demo/" . $userIp . "\n";
$emailBody .= "User Agent: " . $userAgent . "\n\n";
$emailBody .= "----------------------------------------\n";
$emailBody .= "Powered by ArgonPipeline.com\n";

try {
    // 4.1 Authenticate and get the Bearer Token
    $tokenUrl = "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token";
    $tokenData = [
        'client_id'     => $clientId,
        'scope'         => 'https://graph.microsoft.com/.default',
        'client_secret' => $clientSecret,
        'grant_type'    => 'client_credentials'
    ];

    $tokenOptions = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($tokenData)
        ]
    ];
    $tokenContext = stream_context_create($tokenOptions);
    $tokenResponse = file_get_contents($tokenUrl, false, $tokenContext);
    
    if ($tokenResponse === false) {
        throw new Exception("Failed to connect to Microsoft authentication server.");
    }

    $tokenJson = json_decode($tokenResponse, true);
    $accessToken = $tokenJson['access_token'] ?? '';

    // 4.2 Send the Email via Graph API
    $sendUrl = "https://graph.microsoft.com/v1.0/users/" . urlencode($senderEmail) . "/sendMail";
    
    $messageData = [
        'message' => [
            'subject' => $emailSubject,
            'body' => [
                'contentType' => 'Text',
                'content' => $emailBody
            ],
            'toRecipients' => [['emailAddress' => ['address' => $senderEmail]]],
            'replyTo' => [['emailAddress' => ['address' => $email, 'name' => "$firstName $lastName"]]]
        ],
        'saveToSentItems' => 'false'
    ];

    $sendOptions = [
        'http' => [
            'header'  => "Authorization: Bearer {$accessToken}\r\n" .
                         "Content-Type: application/json\r\n",
            'method'  => 'POST',
            'content' => json_encode($messageData),
            'ignore_errors' => true
        ]
    ];
    
    $sendContext = stream_context_create($sendOptions);
    $sendResponse = file_get_contents($sendUrl, false, $sendContext);
    
    // A successful send returns HTTP 202 Accepted. If it doesn't, extract the Microsoft error.
    if (strpos($http_response_header[0], '202') === false) {
        $errorData = json_decode($sendResponse, true);
        throw new Exception($errorData['error']['message'] ?? 'Microsoft Graph API rejected the message.');
    }

// =========================================================================
// 5. SUCCESS RESPONSE
// =========================================================================
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "message" => "Message sent securely."]);
    exit;

} catch (Exception $e) {
    // 1. Log to stderr for Google Cloud Logging
    $errorMessage = 'MAILER ERROR (Rugeley Graph API): ' . $e->getMessage();
    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");
    
    // 2. Send Discord Webhook Alert using robust cURL
    $webhookUrl = getenv('ALERT_WEBHOOK_URL');
    if (!empty($webhookUrl)) {
        $domain = $_SERVER['HTTP_HOST'] ?? 'Unknown Domain';
        $alertPayload = json_encode([
            "content" => "[ALERT] **Rugeley DDS Form Error**\n**Domain:** " . $domain . "\n**Error:** " . $errorMessage
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

    // 3. Return a sanitized JSON response to the front-end (CRITICAL FIX: Removed raw $e->getMessage() exposure)
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}
