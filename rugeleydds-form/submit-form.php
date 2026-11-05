<?php
// CRITICAL: Load Composer's autoloader
if (file_exists(__DIR__ . '/vendor/autoload.php')) { require __DIR__ . '/vendor/autoload.php'; }

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.rugeleydds.com';
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
// 3. READ & SANITIZE PAYLOAD (JSON OR FORM-DATA)
// =========================================================================
$json_payload = file_get_contents('php://input');
$data = json_decode($json_payload, true);
if (!$data && !empty($_POST)) {
    $data = $_POST;
}

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim($data['fax_number']) : '';
if (!empty($honeypot)) {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot.']);
    file_put_contents('php://stderr', $logData . "\n");
    
    header('Content-Type: application/json');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;
}

// --- CLOUDFLARE TURNSTILE VERIFICATION ---
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

// --- DATA NORMALIZATION ---
$formType = isset($data['form_type']) ? trim($data['form_type']) : 'contact';

if (!empty($data['name'])) {
    $parts = explode(' ', trim($data['name']), 2);
    $firstName = $parts[0];
    $lastName  = $parts[1] ?? '';
} else {
    $firstName = trim($data['first_name'] ?? '');
    $lastName  = trim($data['last_name'] ?? '');
}

$email       = filter_var(trim($data['email'] ?? ''), FILTER_VALIDATE_EMAIL);
$phone       = trim($data['phone'] ?? '');
$howYouFind  = trim($data['how_you_find'] ?? '');
$referalName = trim($data['referal_name'] ?? '');
$consent     = trim($data['consent'] ?? '');

$message = trim($data['reason'] ?? ($data['message'] ?? ($data['notes'] ?? '')));

$preferredDate = trim($data['preferred_dates'] ?? ($data['preferred_date'] ?? ''));
$preferredTime = trim($data['preferred_times'] ?? ($data['preferred_time'] ?? ''));
$patientType   = trim($data['patient_type'] ?? '');

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
// 3.2 REQUIRED FIELDS CHECK
// =========================================================================
if (empty($firstName) || empty($lastName) || empty($phone) || empty($message) || empty($howYouFind) || $consent !== 'yes' || !$email) {
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "Please complete all required fields and accept the consent agreement."]);
    exit;
}

// XSS Sanitization
$firstName     = strip_tags($firstName);
$lastName      = strip_tags($lastName);
$phone         = strip_tags($phone);
$howYouFind    = strip_tags($howYouFind);
$referalName   = strip_tags($referalName);
$message       = strip_tags($message);
$preferredDate = strip_tags($preferredDate);
$preferredTime = strip_tags($preferredTime);
$patientType   = strip_tags($patientType);

// =========================================================================
// 4. MICROSOFT GRAPH API DISPATCH
// =========================================================================
$tenantId     = getenv('MS_TENANT_ID');
$clientId     = getenv('MS_CLIENT_ID');
$clientSecret = getenv('MS_CLIENT_SECRET');
$senderEmail  = getenv('MS_SENDER_EMAIL') ?: 'reception@rugeleydds.com';

$fullName = trim("$firstName $lastName");

if ($formType === 'appointment') {
    $emailSubject = "New Appointment Request from $fullName";
    $emailBody  = "You have received a secure appointment request:\n\n";
    $emailBody .= "Patient Status: " . ($patientType ?: 'Not Specified') . "\n";
    $emailBody .= "Name: " . $fullName . "\n";
    $emailBody .= "Email: " . $email . "\n";
    $emailBody .= "Phone: " . $phone . "\n";
    if (!empty($preferredDate)) $emailBody .= "Preferred Date: " . $preferredDate . "\n";
    if (!empty($preferredTime)) $emailBody .= "Preferred Time: " . $preferredTime . "\n";
    $emailBody .= "Found Via: " . $howYouFind . "\n";
    if (!empty($referalName)) $emailBody .= "Referral/Other: " . $referalName . "\n";
} else {
    $emailSubject = "New website message from $fullName";
    $emailBody  = "You have received a secure website message:\n\n";
    $emailBody .= "Name: " . $fullName . "\n";
    $emailBody .= "Email: " . $email . "\n";
    $emailBody .= "Phone: " . $phone . "\n";
    $emailBody .= "Found Via: " . $howYouFind . "\n";
    if (!empty($referalName)) $emailBody .= "Referral/Other: " . $referalName . "\n";
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
    
    $messageData = [
        'message' => [
            'subject' => $emailSubject,
            'body' => [
                'contentType' => 'Text',
                'content'     => $emailBody
            ],
            'toRecipients' => [['emailAddress' => ['address' => $senderEmail]]],
            'bccRecipients' => [['emailAddress' => ['address' => 'art@logicalthings.com']]],
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
    $errorMessage = 'MAILER ERROR (Rugeley Graph API): ' . $e->getMessage();
    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");
    
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
        curl_exec($ch);
        curl_close($ch);
    }

    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}
