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

// =========================================================================
// APPLICATION-LEVEL RATE LIMITING (MAX 5 SUBMISSIONS / 60s PER IP)
// =========================================================================
$rlForwarded = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? "";
$rlRawIp     = $rlForwarded !== "" ? trim(explode(",", $rlForwarded)[0]) : ($_SERVER["REMOTE_ADDR"] ?? "unknown");
$rlHash      = hash("sha256", $rlRawIp . (getenv("CLINIC_NAME") ?: "argon"));
$rlFile      = sys_get_temp_dir() . "/ap_rl_" . $rlHash . ".json";
$rlNow       = time();
$rlWindow    = 60;
$rlMax       = 5;
$rlTimes     = [];
if (file_exists($rlFile)) {
    $rlDec = json_decode((string)@file_get_contents($rlFile), true);
    if (is_array($rlDec)) {
        $rlTimes = array_values(array_filter($rlDec, static fn($ts) => is_int($ts) && ($rlNow - $ts) < $rlWindow));
    }
}
if (count($rlTimes) >= $rlMax) {
    http_response_code(429);
    header("Retry-After: " . $rlWindow);
    echo json_encode(["status" => "error", "success" => false, "message" => "Too many submissions received. Please wait a minute and try again."]);
    exit;
}
$rlTimes[] = $rlNow;
@file_put_contents($rlFile, json_encode($rlTimes), LOCK_EX);


// --- CLOUDFLARE TURNSTILE VERIFICATION ---
$turnstileSecret = getenv('TURNSTILE_SECRET_KEY');
if (!empty($turnstileSecret)) {
    $token = $data['cf-turnstile-response'] ?? '';
    if (empty($token)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'success' => false, 'message' => 'Please complete the security check.']);
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
        
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'success' => false, 'message' => 'Security verification failed. Please try again.']);
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
// 3.2 REQUIRED FIELDS CHECK (WCAG 2.1 AA FIELD-LEVEL ERRORS)
// =========================================================================
$fieldErrors = [];

if ($formType === 'appointment' && $patientType === '') {
    $fieldErrors['patient_type'] = 'Please select a Patient Type.';
}
if ($firstName === '')  $fieldErrors['first_name']   = 'First Name is required.';
if ($lastName === '')   $fieldErrors['last_name']    = 'Last Name is required.';
if (!$email)            $fieldErrors['email']        = 'Enter a valid email address.';
if ($phone === '')      $fieldErrors['phone']        = 'Phone number is required.';

if ($formType === 'appointment') {
    if ($preferredDate === '') $fieldErrors['preferred_dates'] = 'Preferred Dates is required.';
    if ($preferredTime === '') $fieldErrors['preferred_times'] = 'Preferred Times is required.';
}

if ($howYouFind === '') $fieldErrors['how_you_find'] = 'Please select how you found us.';
if ($howYouFind === 'Other' && $referalName === '') {
    $fieldErrors['referal_name'] = 'Please provide your referral or other details.';
}

if ($message === '') {
    $msgKey = ($formType === 'appointment') ? 'reason' : 'message';
    $fieldErrors[$msgKey] = ($formType === 'appointment') ? 'Reason for Visit is required.' : 'Message is required.';
}

if ($consent !== 'yes') {
    $fieldErrors['consent'] = ($formType === 'appointment')
        ? 'You must check the consent box to submit your appointment request.'
        : 'You must check the consent box to submit your message.';
}

if (!empty($fieldErrors)) {
    http_response_code(422);
    header('Content-Type: application/json');
    echo json_encode([
        "status"       => "error",
        "success"      => false,
        "message"      => "Please correct the highlighted fields and try again.",
        "field_errors" => $fieldErrors
    ]);
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
// 4. HTML EMAIL FORMATTING & MICROSOFT GRAPH API DISPATCH
// =========================================================================
$tenantId          = getenv('MS_TENANT_ID');
$clientId          = getenv('MS_CLIENT_ID');
$clientSecret      = getenv('MS_CLIENT_SECRET');
$senderEmail       = getenv('MS_SENDER_EMAIL') ?: 'reception@rugeleydds.com';
$clinicName        = getenv('CLINIC_NAME') ?: 'Rugeley DDS';
$senderDisplayName = getenv('SENDER_NAME') ?: 'Rugeley DDS';

$fullName = trim("$firstName $lastName");

if ($formType === 'appointment') {
    $emailSubject    = "New Appointment Request from {$fullName}";
    $headerSubtitle  = "New Appointment Request Received";
    $fields = [
        'Patient Status'           => ($patientType !== '' ? $patientType : 'Not Specified'),
        'First Name'               => $firstName,
        'Last Name'                => $lastName,
        'Email'                    => (string)$email,
        'Phone'                    => $phone,
        'Preferred Date'           => $preferredDate,
        'Preferred Time'           => $preferredTime,
        'How Did You Find Us?'     => $howYouFind,
        'Referral / Other Details' => $referalName,
        'Message / Notes'          => $message,
    ];
} else {
    $emailSubject    = "New website message from {$fullName}";
    $headerSubtitle  = "New Website Message Received";
    $fields = [
        'First Name'               => $firstName,
        'Last Name'                => $lastName,
        'Email'                    => (string)$email,
        'Phone'                    => $phone,
        'How Did You Find Us?'     => $howYouFind,
        'Referral / Other Details' => $referalName,
        'Message'                  => $message,
    ];
}

$tableRows = '';
foreach ($fields as $label => $cleanVal) {
    if ($cleanVal === '') {
        continue;
    }

    $safeLabel  = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
    $safeVal    = nl2br(htmlspecialchars($cleanVal, ENT_QUOTES, 'UTF-8'));
    $displayVal = $safeVal;

    if ($label === 'Email') {
        $replySubj  = rawurlencode("Re: Website Message - {$clinicName}");
        $displayVal = "<a href=\"mailto:{$safeVal}?subject={$replySubj}\" style=\"color: #554F9B; text-decoration: none; font-weight: 500;\">{$safeVal}</a>";
    } elseif ($label === 'Phone') {
        $telHref = preg_replace('/[^0-9+]/', '', $cleanVal);
        if ($telHref !== '') {
            $displayVal = "<a href=\"tel:{$telHref}\" style=\"color: #554F9B; text-decoration: none; font-weight: 500;\">{$safeVal}</a>";
        }
    }

    $tableRows .= "
      <tr>
        <td style=\"padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;\">{$safeLabel}</td>
        <td style=\"padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;\">{$displayVal}</td>
      </tr>";
}

$safeReplyEmail  = htmlspecialchars((string)$email, ENT_QUOTES, 'UTF-8');
$safeReplyName   = htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8');
$replySubj       = rawurlencode("Re: Website Message - {$clinicName}");
$replyButtonHtml = "
        <div style=\"margin-top: 20px; text-align: left;\">
          <a href=\"mailto:{$safeReplyEmail}?subject={$replySubj}\" style=\"display: inline-block; background: #554F9B; color: #ffffff; text-decoration: none; padding: 10px 18px; border-radius: 4px; font-size: 14px; font-weight: 600;\">Reply to {$safeReplyName}</a>
        </div>";

$tzName = getenv('TIMEZONE') ?: 'America/Chicago';
try {
    $dt = new DateTimeImmutable('now', new DateTimeZone($tzName));
} catch (Exception $e) {
    $dt = new DateTimeImmutable('now', new DateTimeZone('America/Chicago'));
}
$submissionTime = $dt->format('F j, Y, g:i a T');
$safeClientIp   = htmlspecialchars($userIp, ENT_QUOTES, 'UTF-8');

$emailBody = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{$emailSubject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #4A5568; background: #f6f6ff; margin: 0; padding: 24px;">
  <table role="presentation" style="max-width: 620px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; border-collapse: separate; border-spacing: 0; overflow: hidden; width: 100%;">
    <tr>
      <td style="background: #554F9B; padding: 18px 24px; color: #ffffff;">
        <h2 style="margin: 0; font-size: 20px; font-weight: 600;">{$clinicName}</h2>
        <div style="font-size: 14px; opacity: 0.9; margin-top: 2px;">{$headerSubtitle}</div>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 24px;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          {$tableRows}
        </table>
        {$replyButtonHtml}
        <div style="margin-top: 20px; padding: 14px; background: #f6f6ff; border-radius: 4px; font-size: 12px; color: #4A5568; line-height: 1.4;">
          <strong>PHI Consent & Authorization:</strong> The sender acknowledged the risks of communicating via unencrypted communication channels and consented to receive email and phone communications regarding their care.<br>
          <strong>Submitted:</strong> {$submissionTime} | <strong>IP Address:</strong> {$safeClientIp}
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 12px 24px; background: #e6e6f9; border-top: 1px solid #e2e8f0; font-size: 11px; color: #4A5568; text-align: center;">
        Processed securely via <a href="https://argonpipeline.com" style="color: #554F9B; text-decoration: none;">Argon Pipeline</a>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

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
    $tokenContext  = stream_context_create($tokenOptions);
    $tokenResponse = file_get_contents($tokenUrl, false, $tokenContext);

    if ($tokenResponse === false) {
        throw new Exception("Failed to connect to Microsoft authentication server.");
    }

    $tokenJson   = json_decode($tokenResponse, true);
    $accessToken = $tokenJson['access_token'] ?? '';

    $sendUrl = "https://graph.microsoft.com/v1.0/users/" . urlencode($senderEmail) . "/sendMail";

    $messageData = [
        'message' => [
            'subject' => $emailSubject,
            'from'    => [
                'emailAddress' => [
                    'address' => $senderEmail,
                    'name'    => $senderDisplayName
                ]
            ],
            'body' => [
                'contentType' => 'HTML',
                'content'     => $emailBody
            ],
            'toRecipients'  => [['emailAddress' => ['address' => $senderEmail]]],
            'bccRecipients' => [['emailAddress' => ['address' => 'art@logicalthings.com']]],
            'replyTo'       => [['emailAddress' => ['address' => $email, 'name' => $fullName]]]
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
    
    if (empty($http_response_header[0]) || strpos($http_response_header[0], '202') === false) {
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

    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "success" => false, "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}