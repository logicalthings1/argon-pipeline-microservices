<?php
// Load autoloader conditionally
if (file_exists(__DIR__ . '/vendor/autoload.php')) { require __DIR__ . '/vendor/autoload.php'; }

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.argonpipeline.com;https://argonpipeline.com';
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

if (isset($_SERVER['HTTP_HOST'])) {
    $allowed_origins[] = 'https://' . $_SERVER['HTTP_HOST'];
}
$allowed_origins = array_values(array_unique(array_filter($allowed_origins)));

$current_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (empty($current_origin) || !in_array($current_origin, $allowed_origins)) {
    if (empty($current_origin) && isset($_SERVER['HTTP_HOST'])) {
        $current_origin = 'https://' . $_SERVER['HTTP_HOST'];
    } else {
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Invalid Origin - ' . ($current_origin ?: 'No Origin')]);
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
// 3. READ & SANITIZE PAYLOAD
// =========================================================================
$json_payload = file_get_contents('php://input');
$data = json_decode($json_payload, true);
if (!$data && !empty($_POST)) {
    $data = $_POST;
}

// Honeypot trap
$honeypot = isset($data['fax_number']) ? trim($data['fax_number']) : '';
if (!empty($honeypot)) {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot.']);
    file_put_contents('php://stderr', $logData . "\n");
    
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;
}

// Turnstile verification
$turnstileSecret = getenv('TURNSTILE_SECRET_KEY');
if (!empty($turnstileSecret)) {
    $token = $data['cf-turnstile-response'] ?? '';
    if (empty($token)) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'success' => false, 'message' => 'Spam verification token missing.']);
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
        echo json_encode(['status' => 'error', 'success' => false, 'message' => 'Bot challenge verification failed.']);
        exit;
    }
}

// Data normalization
$firstName    = trim($data['first_name'] ?? '');
$lastName     = trim($data['last_name'] ?? '');
$email        = filter_var(trim($data['email'] ?? ''), FILTER_VALIDATE_EMAIL);
$url          = trim($data['url'] ?? '');
$service      = trim($data['service'] ?? '');
$specifyOther = trim($data['specify_other'] ?? '');
$message      = trim($data['message'] ?? '');

// Metadata capture
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $userIp = trim($ipList[0]);
} else {
    $userIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

// Required fields validation
if (empty($firstName) || empty($lastName) || empty($url) || empty($service) || empty($message) || !$email) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Please complete all required fields."]);
    exit;
}

// XSS Sanitization
$firstName    = htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8');
$lastName     = htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8');
$url          = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
$service      = htmlspecialchars($service, ENT_QUOTES, 'UTF-8');
$specifyOther = htmlspecialchars($specifyOther, ENT_QUOTES, 'UTF-8');
$message      = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
$fullName     = trim("$firstName $lastName");

// =========================================================================
// 4. MICROSOFT GRAPH API DISPATCH
// =========================================================================
$tenantId     = getenv('MS_TENANT_ID');
$clientId     = getenv('MS_CLIENT_ID');
$clientSecret = getenv('MS_CLIENT_SECRET');
$senderEmail  = getenv('MS_SENDER_EMAIL') ?: 'info@argonpipeline.com';

$emailSubject = "New Argon Pipeline Inquiry from $fullName";

$emailBody  = "You have received a new inquiry via Argon Pipeline:\n\n";
$emailBody .= "Name: " . $fullName . "\n";
$emailBody .= "Email: " . $email . "\n";
$emailBody .= "Website: " . $url . "\n";
$emailBody .= "Office Suite: " . ucfirst($service) . "\n";
if (!empty($specifyOther)) {
    $emailBody .= "Specified Other Suite: " . $specifyOther . "\n";
}
$emailBody .= "\nMessage:\n" . $message . "\n\n";
$emailBody .= "----------------------------------------\n";
$emailBody .= "IP Address: https://www.ip2location.com/demo/" . htmlspecialchars($userIp, ENT_QUOTES, 'UTF-8') . "\n";
$emailBody .= "User Agent: " . htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8') . "\n";
$emailBody .= "----------------------------------------\n";
$emailBody .= "Powered by ArgonPipeline.com\n";

try {
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

    $sendUrl = "https://graph.microsoft.com/v1.0/users/" . urlencode($senderEmail) . "/sendMail";
    
    // Direct delivery to senderEmail without BCC
    $messageData = [
        'message' => [
            'subject' => $emailSubject,
            'body' => [
                'contentType' => 'Text',
                'content'     => $emailBody
            ],
            'toRecipients' => [['emailAddress' => ['address' => $senderEmail]]],
            'replyTo'      => [['emailAddress' => ['address' => $email, 'name' => $fullName]]]
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
    
    if (strpos($http_response_header[0], '202') === false) {
        $errorData = json_decode($sendResponse, true);
        throw new Exception($errorData['error']['message'] ?? 'Microsoft Graph API rejected the message.');
    }

    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;

} catch (Exception $e) {
    $errorMessage = 'MAILER ERROR (Argon Graph API): ' . $e->getMessage();
    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");
    
    $webhookUrl = getenv('ALERT_WEBHOOK_URL');
    if (!empty($webhookUrl)) {
        $domain = $_SERVER['HTTP_HOST'] ?? 'Unknown Domain';
        $alertPayload = json_encode([
            "content" => "[ALERT] **Argon Form Error**\n**Domain:** " . $domain . "\n**Error:** " . $errorMessage
        ]);
        
        $ch = curl_init($webhookUrl);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $alertPayload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_exec($ch);
        curl_close($ch);
    }

    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}
