<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.marianwthompson.com';
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

        header('Content-Type: application/json; charset=utf-8');
        http_response_code(403);
        echo json_encode([
            "status"  => "error",
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
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method Not Allowed"]);
    exit;
}

// =========================================================================
// 3. READ & SANITIZE THE SECURE PAYLOAD (JSON OR FORM-ENCODED)
// =========================================================================
$rawInput = file_get_contents('php://input');
$data = json_decode((string)$rawInput, true);
if (!is_array($data)) {
    $data = $_POST;
}

// --- HONEYPOT CHECK ---
$honeypot = isset($data['fax_number']) ? trim((string)$data['fax_number']) : '';
if ($honeypot !== '') {
    $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Honeypot triggered by bot. (Hidden fax_number field filled)']);
    file_put_contents('php://stderr', $logData . "\n");

    echo json_encode(["status" => "success", "message" => "Message sent securely."]);
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


// --- DATA SANITIZATION & VALIDATION ---
$firstName   = isset($data['first_name'])   ? trim((string)$data['first_name'])   : '';
$lastName    = isset($data['last_name'])    ? trim((string)$data['last_name'])    : '';
$emailRaw    = isset($data['email'])        ? trim((string)$data['email'])        : '';
$email       = filter_var($emailRaw, FILTER_VALIDATE_EMAIL);
$phone       = isset($data['phone'])        ? trim((string)$data['phone'])        : '';
$howYouFind  = isset($data['how_you_find']) ? trim((string)$data['how_you_find']) : '';
$referalName = isset($data['referal_name']) ? trim((string)$data['referal_name']) : '';
$message     = isset($data['message'])      ? trim((string)$data['message'])      : '';
$consent     = isset($data['consent'])      ? trim((string)$data['consent'])      : '';

// =========================================================================
// 3.1 CAPTURE METADATA (CLIENT IP & TIMEZONE)
// =========================================================================
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $userIp = trim($ipList[0]);
} else {
    $userIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}
$userIp = strip_tags($userIp);

$tzName = getenv('TIMEZONE') ?: 'America/Chicago';
try {
    $dt = new DateTimeImmutable('now', new DateTimeZone($tzName));
} catch (Exception $e) {
    $dt = new DateTimeImmutable('now', new DateTimeZone('America/Chicago'));
}
$submissionTime = $dt->format('F j, Y, g:i a T');

// =========================================================================
// 3.2 TURNSTILE VERIFICATION
// =========================================================================
$turnstileResponse = $data['cf-turnstile-response'] ?? '';
$turnstileSecret   = getenv('TURNSTILE_SECRET') ?: getenv('TURNSTILE_SECRET_KEY') ?: '';

if (!empty($turnstileSecret)) {
    if (empty($turnstileResponse) || !is_string($turnstileResponse) || strlen($turnstileResponse) > 2048) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Please complete the security check."]);
        exit;
    }

    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $turnstileSecret,
            'response' => $turnstileResponse,
            'remoteip' => $userIp
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $verifyResult = curl_exec($ch);
    $curlError    = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        file_put_contents('php://stderr', json_encode(['severity' => 'ERROR', 'message' => 'Turnstile cURL error: ' . $curlError]) . "\n");
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Unable to verify security challenge. Please try again."]);
        exit;
    }

    $cfData = json_decode((string)$verifyResult, true);
    if (empty($cfData['success'])) {
        $logData = json_encode(['severity' => 'ERROR', 'message' => 'SECURITY BLOCK: Turnstile validation failed.']);
        file_put_contents('php://stderr', $logData . "\n");

        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Security verification failed. Please try again."]);
        exit;
    }
}

// =========================================================================
// 3.3 REQUIRED FIELDS CHECK (WCAG 2.1 AA FIELD-LEVEL ERRORS)
// =========================================================================
$fieldErrors = [];
if ($firstName === '')  $fieldErrors['first_name']   = 'First Name is required.';
if ($lastName === '')   $fieldErrors['last_name']    = 'Last Name is required.';
if (!$email)            $fieldErrors['email']        = 'Enter a valid email address.';
if ($phone === '')      $fieldErrors['phone']        = 'Phone Number is required.';
if ($howYouFind === '') $fieldErrors['how_you_find'] = 'Please select how you found me.';
if (($howYouFind === 'Referral' || $howYouFind === 'Other') && $referalName === '') {
    $fieldErrors['referal_name'] = 'Please specify your referral or other details.';
}
if ($message === '')    $fieldErrors['message']      = 'Your Message is required.';
if ($consent !== 'yes') $fieldErrors['consent']      = 'You must accept the communication consent agreement before submitting.';

if (isset($message) && strlen($message) > 5000) { $fieldErrors['message'] = 'Message must be 5,000 characters or fewer.'; }
if (!empty($fieldErrors)) {
    http_response_code(422);
    echo json_encode([
        "status"       => "error",
        "message"      => "Please correct the highlighted fields and try again.",
        "field_errors" => $fieldErrors
    ]);
    exit;
}

$firstName   = strip_tags($firstName);
$lastName    = strip_tags($lastName);
$phone       = strip_tags($phone);
$howYouFind  = strip_tags($howYouFind);
$referalName = strip_tags($referalName);
$message     = strip_tags($message);

// =========================================================================
// 4. HTML EMAIL FORMATTING & PHPMAILER DISPATCH
// =========================================================================
$clinicName        = getenv('CLINIC_NAME') ?: 'Marian W. Thompson';
$senderDisplayName = getenv('SENDER_NAME') ?: 'Marian W. Thompson Contact Form';
$senderName        = trim("$firstName $lastName");
$subject           = "New website message from {$senderName}";

$fields = [
    'First Name'               => $firstName,
    'Last Name'                => $lastName,
    'Email'                    => (string)$email,
    'Phone'                    => $phone,
    'How Did You Find Us?'     => $howYouFind,
    'Referral / Other Details' => $referalName,
    'Message'                  => $message,
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

    $textSummary .= "{$label}: {$cleanVal}\n";
}

$safeReplyEmail  = htmlspecialchars((string)$email, ENT_QUOTES, 'UTF-8');
$safeReplyName   = htmlspecialchars($senderName, ENT_QUOTES, 'UTF-8');
$replySubj       = rawurlencode("Re: Website Message - {$clinicName}");
$replyButtonHtml = "
        <div style=\"margin-top: 20px; text-align: left;\">
          <a href=\"mailto:{$safeReplyEmail}?subject={$replySubj}\" style=\"display: inline-block; background: #554F9B; color: #ffffff; text-decoration: none; padding: 10px 18px; border-radius: 4px; font-size: 14px; font-weight: 600;\">Reply to {$safeReplyName}</a>
        </div>";

$safeClientIp = htmlspecialchars($userIp, ENT_QUOTES, 'UTF-8');

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

$textSummary .= "\n" . str_repeat('=', 40) . "\nConsent Accepted: Yes\nSubmitted: {$submissionTime}\nIP Address: {$userIp}\n";

$smtpHost  = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpUser  = getenv('SMTP_USER') ?: 'me@marianwthompson.com';
$smtpPass  = getenv('SMTP_PASS');
$smtpPort  = (int)(getenv('SMTP_PORT') ?: 465);
$recipient = getenv('RECIPIENT_EMAIL') ?: 'me@marianwthompson.com';
$bcc       = getenv('BCC_EMAIL') ?: '';

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

    foreach (explode(',', $recipient) as $recip) {
        $clean = trim($recip);
        if ($clean !== '') {
            $mail->addAddress($clean);
        }
    }

    if (!empty($bcc)) {
        foreach (explode(',', $bcc) as $bccItem) {
            $cleanBcc = trim($bccItem);
            if ($cleanBcc !== '') {
                $mail->addBCC($cleanBcc);
            }
        }
    }

    $mail->addReplyTo((string)$email, $senderName);

    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body    = $htmlBody;
    $mail->AltBody = $textSummary;

    $mail->send();

    // Optional Non-PHI SEO/AEO Attribution Receipt (HIPAA Safe Harbor De-Identified)
    $seoRecipient = trim(getenv('SEO_ATTRIBUTION_EMAIL') ?: '');
    if ($seoRecipient !== '') {
        $seoFormType  = isset($formType) && $formType !== '' ? $formType : 'Website Inquiry';
        $safeSource   = htmlspecialchars($howYouFind, ENT_QUOTES, 'UTF-8');
        $safeReferral = htmlspecialchars($referalName !== '' ? $referalName : 'N/A', ENT_QUOTES, 'UTF-8');
        $safeFormType = htmlspecialchars($seoFormType, ENT_QUOTES, 'UTF-8');
        $seoSubject   = preg_replace('/[\r\n\0]+/', ' ', "[Lead Attribution] {$clinicName} - {$howYouFind}");
        $seoHtml      = <<<HTML
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #333; padding: 20px;">
  <h3 style="margin-top: 0; color: #554F9B;">De-Identified Lead Attribution: {$clinicName}</h3>
  <p style="font-size: 13px; color: #555;">HIPAA Safe Harbor Notice: All patient identifiers and clinical message contents have been stripped from this analytics receipt.</p>
  <table style="border-collapse: collapse; width: 100%; max-width: 500px;">
    <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: 600;">Clinic</td><td style="padding: 8px; border: 1px solid #ddd;">{$clinicName}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: 600;">Form Type</td><td style="padding: 8px; border: 1px solid #ddd;">{$safeFormType}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: 600;">How Found</td><td style="padding: 8px; border: 1px solid #ddd;">{$safeSource}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: 600;">Referral / Source Detail</td><td style="padding: 8px; border: 1px solid #ddd;">{$safeReferral}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: 600;">Submitted</td><td style="padding: 8px; border: 1px solid #ddd;">{$submissionTime}</td></tr>
  </table>
</body>
</html>
HTML;
        $seoText = "De-Identified Lead Attribution: {$clinicName}\nForm Type: {$seoFormType}\nHow Found: {$howYouFind}\nReferral Detail: " . ($referalName !== '' ? $referalName : 'N/A') . "\nSubmitted: {$submissionTime}\n";

        try {
            $seoMail = new PHPMailer\PHPMailer\PHPMailer(true);
            $seoMail->isSMTP();
            $seoMail->Host       = $smtpHost;
            $seoMail->SMTPAuth   = true;
            $seoMail->Username   = $smtpUser;
            $seoMail->Password   = $smtpPass;
            $seoMail->Port       = $smtpPort;
            $seoMail->SMTPSecure = ($smtpPort === 465) ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $seoMail->CharSet    = 'UTF-8';
            $seoMail->setFrom($smtpUser, $senderName);
            foreach (explode(',', $seoRecipient) as $addr) {
                $clean = filter_var(trim($addr), FILTER_VALIDATE_EMAIL);
                if ($clean) $seoMail->addAddress($clean);
            }
            $seoMail->isHTML(true);
            $seoMail->Subject = $seoSubject;
            $seoMail->Body    = $seoHtml;
            $seoMail->AltBody = $seoText;
            $seoMail->send();
        } catch (Throwable $seoEx) {
            file_put_contents('php://stderr', json_encode([
                'severity' => 'WARNING',
                'message'  => 'SEO attribution dispatch failed: ' . $seoEx->getMessage()
            ]) . "\n");
        }
    }


    echo json_encode(["status" => "success", "message" => "Message sent securely."]);
    exit;

} catch (Exception $e) {
    $detailedError = (isset($mail) && !empty($mail->ErrorInfo)) ? $mail->ErrorInfo : $e->getMessage();
    $errorMessage  = 'MAILER ERROR: ' . $detailedError;

    $logData = json_encode(['severity' => 'ERROR', 'message' => $errorMessage]);
    file_put_contents('php://stderr', $logData . "\n");

    $webhookUrl = getenv('ALERT_WEBHOOK_URL') ?: getenv('DISCORD_WEBHOOK_URL');
    if (!empty($webhookUrl)) {
        $domain       = $_SERVER['HTTP_HOST'] ?? 'Unknown Domain';
        $alertPayload = json_encode([
            "content" => "[ALERT] **MWT Form Error**\n**Domain:** " . $domain . "\n**Error:** " . $errorMessage
        ]);

        $ch = curl_init($webhookUrl);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $alertPayload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        $discordResponse = curl_exec($ch);
        $httpCode        = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode < 200 || $httpCode >= 300) {
            $discordLog = json_encode(['severity' => 'WARNING', 'message' => 'Discord Webhook Failed. HTTP: ' . $httpCode . ' Response: ' . $discordResponse]);
            file_put_contents('php://stderr', $discordLog . "\n");
        }
    }

    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "An internal system error prevented this message from sending. Our team has been immediately notified."]);
    exit;
}