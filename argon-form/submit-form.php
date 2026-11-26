<?php
declare(strict_types=1);

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

if (empty($current_origin) || !in_array($current_origin, $allowed_origins, true)) {
    if (empty($current_origin) && isset($_SERVER['HTTP_HOST'])) {
        $current_origin = 'https://' . $_SERVER['HTTP_HOST'];
    } else {
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Invalid Origin attempted - ' . ($current_origin ?: 'No Origin')]);
        file_put_contents('php://stderr', $logData . "\n");
        
        http_response_code(403);
        header('X-Content-Type-Options: nosniff');
        header('Content-Type: application/json; charset=utf-8');
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
header("X-Content-Type-Options: nosniff");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST, OPTIONS');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "Method Not Allowed."]);
    exit;
}

// =========================================================================
// 2.5 MAX PAYLOAD SIZE GUARD (64 KB CAP AGAINST MEMORY / EMAIL BLOAT)
// =========================================================================
$maxPayloadBytes = 65536;
$contentLength   = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
if ($contentLength > $maxPayloadBytes) {
    http_response_code(413);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "Submission payload exceeds maximum allowed size."]);
    exit;
}

// =========================================================================
// 3. READ & SANITIZE THE SECURE JSON PAYLOAD
// =========================================================================
$json_payload = file_get_contents('php://input', false, null, 0, $maxPayloadBytes + 1);
if ($json_payload !== false && strlen($json_payload) > $maxPayloadBytes) {
    http_response_code(413);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "Submission payload exceeds maximum allowed size."]);
    exit;
}
$data = json_decode((string)$json_payload, true);
if (!is_array($data) && !empty($_POST)) {
    $data = $_POST;
}
if (!is_array($data)) {
    $data = [];
}

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim((string)$data['fax_number']) : '';
if ($honeypot !== '') {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot. (Hidden fax_number field filled)']);
    file_put_contents('php://stderr', $logData . "\n");
    
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "success", "success" => true, "message" => "Message sent securely."]);
    exit;
}

// =========================================================================
// 3.1 APPLICATION-LEVEL RATE LIMITING (MAX 5 SUBMISSIONS / 60s PER IP)
// =========================================================================
$rlForwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$rlRawIp     = $rlForwarded !== '' ? trim(explode(',', $rlForwarded)[0]) : ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$rlHash      = hash('sha256', $rlRawIp . (getenv('CLINIC_NAME') ?: 'argon'));
$rlFile      = sys_get_temp_dir() . '/ap_rl_' . $rlHash . '.json';
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
    header('Retry-After: ' . $rlWindow);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        "status"  => "error",
        "success" => false,
        "message" => "Too many submissions received. Please wait a minute and try again."
    ]);
    exit;
}

$rlTimes[] = $rlNow;
@file_put_contents($rlFile, json_encode($rlTimes), LOCK_EX);

// =========================================================================
// 3.2 CAPTURE METADATA (IP & USER AGENT)
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
$turnstileSecret   = getenv('TURNSTILE_SECRET') ?: getenv('TURNSTILE_SECRET_KEY') ?: '';

if (empty($turnstileResponse) || !is_string($turnstileResponse) || strlen($turnstileResponse) > 2048) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "Please complete the security check."]);
    exit;
}

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
        'content' => http_build_query($verifyData),
        'timeout' => 5
    ]
];
$context      = stream_context_create($options);
$verifyResult = file_get_contents($verifyUrl, false, $context);
$cfData       = json_decode((string)$verifyResult, true);

if (empty($cfData['success'])) {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Turnstile validation failed.']);
    file_put_contents('php://stderr', $logData . "\n");

    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "Security verification failed. Please try again."]);
    exit;
}

// =========================================================================
// 5. DATA SANITIZATION & VALIDATION (WCAG 2.1 AA FIELD-LEVEL ERRORS)
// =========================================================================
$firstName    = isset($data['first_name']) ? trim((string)$data['first_name']) : '';
$lastName     = isset($data['last_name']) ? trim((string)$data['last_name']) : '';
$email        = isset($data['email']) ? filter_var(trim((string)$data['email']), FILTER_VALIDATE_EMAIL) : false;
$url          = isset($data['url']) ? trim((string)$data['url']) : '';
$service      = isset($data['service']) ? trim((string)$data['service']) : '';
$specifyOther = isset($data['specify_other']) ? trim((string)$data['specify_other']) : '';
$message      = isset($data['message']) ? trim((string)$data['message']) : '';

$fieldErrors = [];
if ($firstName === '') $fieldErrors['first_name'] = 'First Name is required.';
if ($lastName === '')  $fieldErrors['last_name']  = 'Last Name is required.';
if (!$email)           $fieldErrors['email']      = 'Enter a valid email address.';
if ($url === '')       $fieldErrors['url']        = 'Website URL is required.';
if ($service === '')   $fieldErrors['service']    = 'Please select your current email or office suite.';
if ($service === 'other' && $specifyOther === '') {
    $fieldErrors['specify_other'] = 'Please specify your email or office suite.';
}
if ($message === '')   $fieldErrors['message']    = 'Question or Comment is required.';

if (isset($message) && strlen($message) > 5000) { $fieldErrors['message'] = 'Message must be 5,000 characters or fewer.'; }
if (!empty($fieldErrors)) {
    http_response_code(422);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        "status"       => "error",
        "success"      => false,
        "message"      => "Please correct the highlighted fields and try again.",
        "field_errors" => $fieldErrors
    ]);
    exit;
}

$firstName    = strip_tags($firstName);
$lastName     = strip_tags($lastName);
$url          = strip_tags($url);
$service      = strip_tags($service);
$specifyOther = strip_tags($specifyOther);
$message      = strip_tags($message);

// =========================================================================
// 6. HTML EMAIL FORMATTING & PHPMAILER PROCESSING (HEADER-INJECTION SAFE)
// =========================================================================
function sanitizeHeaderStr(string $val): string {
    return trim((string)preg_replace('/[\r\n\0]+/', ' ', $val));
}

$clinicName        = sanitizeHeaderStr(getenv('CLINIC_NAME') ?: 'Argon Pipeline');
$senderDisplayName = sanitizeHeaderStr(getenv('SENDER_NAME') ?: 'Argon Pipeline System');
$senderName        = sanitizeHeaderStr(trim("$firstName $lastName"));
$cleanReplyEmail   = sanitizeHeaderStr((string)$email);
$subject           = sanitizeHeaderStr("New website message from {$senderName}");

$fields = [
    'First Name'            => $firstName,
    'Last Name'             => $lastName,
    'Email'                 => $cleanReplyEmail,
    'Website URL'           => $url,
    'Office Suite'          => ucfirst($service),
    'Specified Other Suite' => $specifyOther,
    'Message'               => $message,
];

$tableRows   = '';
$textSummary = "NEW WEBSITE MESSAGE: {$clinicName}\n" . str_repeat('=', 40) . "\n\n";

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
    } elseif ($label === 'Website URL') {
        $hrefUrl = preg_match('~^https?://~i', $cleanVal) ? $cleanVal : 'https://' . $cleanVal;
        if (filter_var($hrefUrl, FILTER_VALIDATE_URL)) {
            $safeHref   = htmlspecialchars($hrefUrl, ENT_QUOTES, 'UTF-8');
            $displayVal = "<a href=\"{$safeHref}\" target=\"_blank\" rel=\"noopener\" style=\"color: #554F9B; text-decoration: none; font-weight: 500;\">{$safeVal}</a>";
        }
    }

    $tableRows .= "
      <tr>
        <td style=\"padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;\">{$safeLabel}</td>
        <td style=\"padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;\">{$displayVal}</td>
      </tr>";

    $textSummary .= "{$label}: {$cleanVal}\n";
}

$safeReplyEmail  = htmlspecialchars($cleanReplyEmail, ENT_QUOTES, 'UTF-8');
$safeReplyName   = htmlspecialchars($senderName, ENT_QUOTES, 'UTF-8');
$replySubj       = rawurlencode("Re: Website Message - {$clinicName}");
$replyButtonHtml = "
        <div style=\"margin-top: 20px; text-align: left;\">
          <a href=\"mailto:{$safeReplyEmail}?subject={$replySubj}\" style=\"display: inline-block; background: #554F9B; color: #ffffff; text-decoration: none; padding: 10px 18px; border-radius: 4px; font-size: 14px; font-weight: 600;\">Reply to {$safeReplyName}</a>
        </div>";

$safeClientIp = htmlspecialchars(strip_tags($userIp), ENT_QUOTES, 'UTF-8');

$tzName = getenv('TIMEZONE') ?: 'America/Chicago';
try {
    $dt = new DateTimeImmutable('now', new DateTimeZone($tzName));
} catch (Exception $e) {
    $dt = new DateTimeImmutable('now', new DateTimeZone('America/Chicago'));
}
$submissionTime = $dt->format('F j, Y, g:i a T');

$htmlBody = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{$subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #4A5568; background: #f6f6ff; margin: 0; padding: 24px;">
  <table role="presentation" style="max-width: 620px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; border-collapse: separate; border-spacing: 0; overflow: hidden; width: 100%;">
    <tr>
      <td style="background: #554F9B; padding: 18px 24px; color: #ffffff;">
        <h2 style="margin: 0; font-size: 20px; font-weight: 600;">{$clinicName}</h2>
        <div style="font-size: 14px; opacity: 0.9; margin-top: 2px;">New Website Message Received</div>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 24px;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          {$tableRows}
        </table>
        {$replyButtonHtml}
        <div style="margin-top: 20px; padding: 14px; background: #f6f6ff; border-radius: 4px; font-size: 12px; color: #4A5568; line-height: 1.4;">
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

$textSummary .= "\n" . str_repeat('=', 40) . "\nSubmitted: {$submissionTime}\nIP Address: {$userIp}\n";

$smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpUser = getenv('SMTP_USER') ?: 'art@logicalthings.com';
$smtpPass = getenv('SMTP_PASS');
$smtpPort = (int)(getenv('SMTP_PORT') ?: 465);

try {
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

    $mail->CharSet    = 'UTF-8';
    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    $mail->Port       = $smtpPort;
    $mail->SMTPSecure = ($smtpPort === 465)
        ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
        : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;

    $mail->setFrom($smtpUser, $senderDisplayName);
    $mail->addAddress('art@logicalthings.com');
    $mail->addReplyTo($cleanReplyEmail, $senderName);

    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body    = $htmlBody;
    $mail->AltBody = $textSummary;

    $mail->send();

// =========================================================================
// 7. SUCCESS RESPONSE
// =========================================================================
    header('Content-Type: application/json; charset=utf-8');
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

    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(["status" => "error", "success" => false, "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}
