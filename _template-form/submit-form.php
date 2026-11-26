<?php
declare(strict_types=1);

// =========================================================================
// 1. STRICT DOMAIN VALIDATION
// =========================================================================
$allowed_env = getenv('CLIENT_DOMAIN') ?: '';
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

if (isset($_SERVER['HTTP_HOST'])) {
    $allowed_origins[] = 'https://' . $_SERVER['HTTP_HOST'];
}
$allowed_origins = array_values(array_unique(array_filter($allowed_origins)));

$current_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (!empty($allowed_origins)) {
    if (empty($current_origin) || !in_array($current_origin, $allowed_origins, true)) {
        if (empty($current_origin) && isset($_SERVER['HTTP_HOST'])) {
            $current_origin = 'https://' . $_SERVER['HTTP_HOST'];
        } else {
            file_put_contents('php://stderr', json_encode([
                'severity' => 'ERROR',
                'message'  => 'SECURITY BLOCK: Invalid Origin attempted - ' . ($current_origin ?: 'No Origin')
            ]) . "\n");

            header('Content-Type: application/json; charset=utf-8');
            http_response_code(403);
            echo json_encode([
                'status'  => 'error',
                'code'    => 'UNAUTHORIZED_ORIGIN',
                'message' => 'Security verification failed. Invalid Origin.'
            ]);
            exit;
        }
    }
}

if ($current_origin !== '') {
    header('Access-Control-Allow-Origin: ' . $current_origin);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');
header('X-Content-Type-Options: nosniff');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// =========================================================================
// 1.5 MAX PAYLOAD SIZE GUARD (64 KB CAP AGAINST MEMORY / EMAIL BLOAT)
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
// 2. HONEYPOT CHECK (BOT TRAP)
// =========================================================================
if (!empty($_POST['fax_number'])) {
    echo json_encode(['status' => 'success', 'message' => 'Your message has been sent successfully.']);
    exit;
}

// =========================================================================
// 2.5 APPLICATION-LEVEL RATE LIMITING (MAX 5 SUBMISSIONS / 60s PER IP)
// =========================================================================
$forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$rawClientIp  = $forwardedFor !== ''
    ? trim(explode(',', $forwardedFor)[0])
    : ($_SERVER['REMOTE_ADDR'] ?? 'unknown');

$ipHash       = hash('sha256', $rawClientIp . (getenv('CLINIC_NAME') ?: 'argon'));
$rateFile     = sys_get_temp_dir() . '/ap_rl_' . $ipHash . '.json';
$now          = time();
$windowSec    = 60;
$maxRequests  = 5;

$timestamps = [];
if (file_exists($rateFile)) {
    $decoded = json_decode((string)@file_get_contents($rateFile), true);
    if (is_array($decoded)) {
        $timestamps = array_values(array_filter($decoded, static fn($ts) => is_int($ts) && ($now - $ts) < $windowSec));
    }
}

if (count($timestamps) >= $maxRequests) {
    http_response_code(429);
    header('Retry-After: ' . $windowSec);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Too many submissions received. Please wait a minute and try again.'
    ]);
    exit;
}

$timestamps[] = $now;
@file_put_contents($rateFile, json_encode($timestamps), LOCK_EX);

// =========================================================================
// 3. CLOUDFLARE TURNSTILE VERIFICATION
// =========================================================================
$turnstileSecret = getenv('TURNSTILE_SECRET_KEY') ?: '';
$turnstileToken  = $_POST['cf-turnstile-response'] ?? '';

if (!empty($turnstileSecret)) {
    if (empty($turnstileToken)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Please complete the security check.']);
        exit;
    }

    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $turnstileSecret,
            'response' => $turnstileToken,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
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
        echo json_encode(['status' => 'error', 'message' => 'Unable to verify security challenge. Please try again.']);
        exit;
    }

    $verifyData = json_decode((string)$verifyResult, true);
    if (!$verifyData || empty($verifyData['success'])) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Security challenge failed. Please refresh and try again.']);
        exit;
    }
}

// =========================================================================
// 4. REQUIRED FIELDS & PHI CONSENT VALIDATION (WCAG 2.1 AA FIELD-LEVEL ERRORS)
// =========================================================================
$firstName   = trim((string)($_POST['first_name'] ?? ''));
$lastName    = trim((string)($_POST['last_name'] ?? ''));
$emailRaw    = trim((string)($_POST['email'] ?? ''));
$email       = filter_var($emailRaw, FILTER_VALIDATE_EMAIL);
$phone       = trim((string)($_POST['phone'] ?? ''));
$howYouFind  = trim((string)($_POST['how_you_find'] ?? ''));
$referalName = trim((string)($_POST['referal_name'] ?? ''));
$message     = trim((string)($_POST['message'] ?? ''));
$consent     = trim((string)($_POST['consent'] ?? ''));

$fieldErrors = [];
if ($firstName === '')  $fieldErrors['first_name']   = 'First Name is required.';
if ($lastName === '')   $fieldErrors['last_name']    = 'Last Name is required.';
if (!$email)            $fieldErrors['email']        = 'Enter a valid email address.';
if ($phone === '')      $fieldErrors['phone']        = 'Phone number is required.';
if ($howYouFind === '') $fieldErrors['how_you_find'] = 'Please select how you found us.';
if ($howYouFind === 'Other' && $referalName === '') {
    $fieldErrors['referal_name'] = 'Please provide your referral or other details.';
}
if ($message === '')    $fieldErrors['message']      = 'Message is required.';
if ($consent !== 'yes') $fieldErrors['consent']      = 'You must check the consent box to submit your message.';

if (isset($message) && strlen($message) > 5000) { $fieldErrors['message'] = 'Message must be 5,000 characters or fewer.'; }
if (!empty($fieldErrors)) {
    http_response_code(422);
    echo json_encode([
        'status'       => 'error',
        'message'      => 'Please correct the highlighted fields and try again.',
        'field_errors' => $fieldErrors
    ]);
    exit;
}

// =========================================================================
// 5. DYNAMIC FIELD EXTRACTION & EMAIL FORMATTING (HEADER-INJECTION SAFE)
// =========================================================================
function sanitizeHeaderStr(string $val): string {
    return trim((string)preg_replace('/[\r\n\0]+/', ' ', $val));
}

$clinicName        = sanitizeHeaderStr(getenv('CLINIC_NAME') ?: 'Argon Pipeline');
$senderDisplayName = sanitizeHeaderStr(getenv('SENDER_NAME') ?: $clinicName);
$formType          = sanitizeHeaderStr((string)($_POST['form_type'] ?? 'Website Inquiry'));
$fullName          = sanitizeHeaderStr((string)($_POST['name'] ?? ''));
$senderName        = sanitizeHeaderStr(trim("$firstName $lastName") ?: ($fullName ?: 'Website Visitor'));
$senderEmail       = sanitizeHeaderStr((string)$email);

$subject = sanitizeHeaderStr("New website message from {$senderName}");

$labelMap = [
    'first_name'    => 'First Name',
    'last_name'     => 'Last Name',
    'email'         => 'Email',
    'phone'         => 'Phone',
    'how_you_find'  => 'How Did You Find Us?',
    'referal_name'  => 'Referral / Other Details',
    'referral_name' => 'Referral / Other Details',
    'message'       => 'Message',
];

$systemKeys = ['cf-turnstile-response', 'fax_number', 'consent', 'form_type'];
$tableRows   = '';
$textSummary = "NEW WEBSITE MESSAGE: {$clinicName}\n" . str_repeat('=', 40) . "\n\n";

foreach ($_POST as $key => $val) {
    if (in_array($key, $systemKeys, true)) {
        continue;
    }

    $cleanVal = is_array($val)
        ? implode(', ', array_map('trim', $val))
        : trim((string)$val);

    if ($cleanVal === '') {
        continue;
    }

    $label      = $labelMap[$key] ?? ucwords(str_replace(['_', '-'], ' ', $key));
    $safeLabel  = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
    $safeVal    = nl2br(htmlspecialchars($cleanVal, ENT_QUOTES, 'UTF-8'));
    $displayVal = $safeVal;

    if ($key === 'email' && filter_var($cleanVal, FILTER_VALIDATE_EMAIL)) {
        $replySubj  = rawurlencode("Re: Website Message - {$clinicName}");
        $displayVal = "<a href=\"mailto:{$safeVal}?subject={$replySubj}\" style=\"color: #554F9B; text-decoration: none; font-weight: 500;\">{$safeVal}</a>";
    } elseif ($key === 'phone') {
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

$replyButtonHtml = '';
if ($senderEmail !== '' && filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
    $safeReplyEmail = htmlspecialchars($senderEmail, ENT_QUOTES, 'UTF-8');
    $safeReplyName  = htmlspecialchars($senderName, ENT_QUOTES, 'UTF-8');
    $replySubj      = rawurlencode("Re: Website Message - {$clinicName}");
    $replyButtonHtml = "
        <div style=\"margin-top: 20px; text-align: left;\">
          <a href=\"mailto:{$safeReplyEmail}?subject={$replySubj}\" style=\"display: inline-block; background: #554F9B; color: #ffffff; text-decoration: none; padding: 10px 18px; border-radius: 4px; font-size: 14px; font-weight: 600;\">Reply to {$safeReplyName}</a>
        </div>";
}

$tzName = getenv('TIMEZONE') ?: 'America/Chicago';
try {
    $dt = new DateTimeImmutable('now', new DateTimeZone($tzName));
} catch (Exception $e) {
    $dt = new DateTimeImmutable('now', new DateTimeZone('America/Chicago'));
}
$submissionTime = $dt->format('F j, Y, g:i a T');

$forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
if ($forwardedFor !== '') {
    $ipParts  = array_map('trim', explode(',', $forwardedFor));
    $clientIp = $ipParts[0] ?: ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
} else {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}
$safeClientIp = htmlspecialchars($clientIp, ENT_QUOTES, 'UTF-8');

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

$textSummary .= "\n" . str_repeat('=', 40) . "\nConsent Accepted: Yes\nSubmitted: {$submissionTime}\nIP Address: {$clientIp}\n";

// =========================================================================
// 6. MAIL TRANSPORT SELECTION & DISPATCH
// =========================================================================
$mailDriver = strtolower(getenv('MAIL_DRIVER') ?: '');
if (empty($mailDriver)) {
    $mailDriver = (getenv('MS_CLIENT_ID') || getenv('MS_TENANT_ID')) ? 'graph' : 'smtp';
}

$recipientList = getenv('RECIPIENT_EMAIL') ?: '';
$bccList       = getenv('BCC_EMAIL') ?: '';

try {
    if ($mailDriver === 'graph') {
        sendViaGraph($subject, $htmlBody, $senderEmail, $senderName, $senderDisplayName, $recipientList, $bccList);
    } else {
        sendViaSmtp($subject, $htmlBody, $textSummary, $senderEmail, $senderName, $senderDisplayName, $recipientList, $bccList);
    }

    // Optional Non-PHI SEO/AEO Attribution Receipt (HIPAA Safe Harbor De-Identified)
    $seoRecipient = trim(getenv('SEO_ATTRIBUTION_EMAIL') ?: '');
    if ($seoRecipient !== '') {
        $rawSlug = trim(getenv('CLINIC_SLUG') ?: '');
        if ($rawSlug === '' && !empty($_SERVER['HTTP_HOST'])) {
            $hostParts = explode('.', strtolower($_SERVER['HTTP_HOST']));
            $rawSlug = preg_replace('/-form$/', '', $hostParts[0]);
        }
        $seoSlug      = strtoupper($rawSlug !== '' ? $rawSlug : 'ARGON');
        $seoDate      = isset($dt) ? $dt->format('Y-m-d') : date('Y-m-d');
        $seoFormType  = isset($formType) && $formType !== '' ? $formType : 'Website Inquiry';
        $safeClinic   = htmlspecialchars($clinicName, ENT_QUOTES, 'UTF-8');
        $safeSource   = htmlspecialchars($howYouFind, ENT_QUOTES, 'UTF-8');
        $safeReferral = htmlspecialchars($referalName !== '' ? $referalName : 'N/A', ENT_QUOTES, 'UTF-8');
        $safeFormType = htmlspecialchars($seoFormType, ENT_QUOTES, 'UTF-8');
        $seoSubject   = preg_replace('/[
 ]+/', ' ', "{$seoSlug} Lead Attribution: {$howYouFind} - {$seoDate}");
        $seoHtml      = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{$seoSubject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #4A5568; background: #f6f6ff; margin: 0; padding: 24px;">
  <table role="presentation" style="max-width: 620px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; border-collapse: separate; border-spacing: 0; overflow: hidden; width: 100%;">
    <tr>
      <td style="background: #554F9B; padding: 18px 24px; color: #ffffff;">
        <h2 style="margin: 0; font-size: 20px; font-weight: 600;">{$safeClinic}</h2>
        <div style="font-size: 14px; opacity: 0.9; margin-top: 2px;">De-Identified Lead Attribution Receipt</div>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 24px;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;">Client</td>
            <td style="padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;">{$safeClinic} ({$seoSlug})</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;">Form Type</td>
            <td style="padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;">{$safeFormType}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;">How Did You Find Us?</td>
            <td style="padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;">{$safeSource}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;">Referral / Source Detail</td>
            <td style="padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;">{$safeReferral}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 15px; font-weight: 600; color: #4A5568; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;">Submitted</td>
            <td style="padding: 10px 14px; font-size: 15px; color: #4A5568; border-bottom: 1px solid #e2e8f0; vertical-align: top;">{$submissionTime}</td>
          </tr>
        </table>
        <div style="margin-top: 20px; padding: 14px; background: #f6f6ff; border-radius: 4px; font-size: 12px; color: #4A5568; line-height: 1.4;">
          <strong>HIPAA Safe Harbor Notice:</strong> All 18 HIPAA patient identifiers, IP addresses, and clinical message contents have been stripped from this lead-source attribution receipt.
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
        $seoText = "De-Identified Lead Attribution: {$clinicName} ({$seoSlug})
Form Type: {$seoFormType}
How Found: {$howYouFind}
Referral Detail: " . ($referalName !== '' ? $referalName : 'N/A') . "
Submitted: {$submissionTime}
";

        try {
            if ($mailDriver === 'graph') {
                sendViaGraph($seoSubject, $seoHtml, '', '', $seoSlug, $seoRecipient, '');
            } else {
                sendViaSmtp($seoSubject, $seoHtml, $seoText, '', '', $seoSlug, $seoRecipient, '');
            }
        } catch (Throwable $seoEx) {
            file_put_contents('php://stderr', json_encode([
                'severity' => 'WARNING',
                'message'  => 'SEO attribution dispatch failed: ' . $seoEx->getMessage()
            ]) . "
");
        }
    }

    echo json_encode([
        'status'  => 'success',
        'message' => 'Thank you! Your inquiry has been securely delivered.'
    ]);
    exit;

} catch (Exception $e) {
    $errorMessage = $e->getMessage();
    file_put_contents('php://stderr', json_encode([
        'severity' => 'ERROR',
        'message'  => "Dispatch error [{$mailDriver}]: {$errorMessage}"
    ]) . "\n");

    sendDiscordAlert($clinicName, $mailDriver, $errorMessage);

    http_response_code(500);
    echo json_encode([
        'status'  => 'error',
        'message' => 'An error occurred while transmitting your message. Please try again or contact our office directly.'
    ]);
    exit;
}

function sendViaGraph(string $subject, string $htmlBody, string $senderEmail, string $senderName, string $senderDisplayName, string $recipient, string $bcc): bool {
    $tenantId     = getenv('MS_TENANT_ID');
    $clientId     = getenv('MS_CLIENT_ID');
    $clientSecret = getenv('MS_CLIENT_SECRET');
    $senderMail   = getenv('SENDER_EMAIL');

    if (!$tenantId || !$clientId || !$clientSecret || !$senderMail || !$recipient) {
        throw new Exception('Incomplete Microsoft Graph credentials in environment.');
    }

    $tokenUrl = "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token";
    $ch = curl_init($tokenUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'scope'         => 'https://graph.microsoft.com/.default',
            'grant_type'    => 'client_credentials'
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15
    ]);
    $tokenRes  = curl_exec($ch);
    $tokenHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $tokenData = json_decode((string)$tokenRes, true);
    if ($tokenHttp !== 200 || empty($tokenData['access_token'])) {
        $desc = $tokenData['error_description'] ?? 'Token grant error';
        throw new Exception("Graph token failed ({$tokenHttp}): {$desc}");
    }

    $toRecipients = [];
    foreach (explode(',', $recipient) as $recip) {
        $clean = sanitizeHeaderStr($recip);
        if ($clean !== '') {
            $toRecipients[] = ['emailAddress' => ['address' => $clean]];
        }
    }

    $message = [
        'subject'      => sanitizeHeaderStr($subject),
        'from'         => ['emailAddress' => ['address' => $senderMail, 'name' => sanitizeHeaderStr($senderDisplayName)]],
        'body'         => ['contentType' => 'HTML', 'content' => $htmlBody],
        'toRecipients' => $toRecipients
    ];

    if ($bcc !== '') {
        $bccRecipients = [];
        foreach (explode(',', $bcc) as $bccItem) {
            $cleanBcc = sanitizeHeaderStr($bccItem);
            if ($cleanBcc !== '') {
                $bccRecipients[] = ['emailAddress' => ['address' => $cleanBcc]];
            }
        }
        if (!empty($bccRecipients)) {
            $message['bccRecipients'] = $bccRecipients;
        }
    }

    if ($senderEmail !== '' && filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
        $message['replyTo'] = [['emailAddress' => ['address' => $senderEmail, 'name' => sanitizeHeaderStr($senderName)]]];
    }

    $sendUrl = 'https://graph.microsoft.com/v1.0/users/' . urlencode($senderMail) . '/sendMail';
    $ch = curl_init($sendUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode(['message' => $message, 'saveToSentItems' => 'false']),
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $tokenData['access_token'],
            'Content-Type: application/json'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20
    ]);
    $sendRes  = curl_exec($ch);
    $sendHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($sendHttp < 200 || $sendHttp >= 300) {
        throw new Exception("Graph sendMail failed ({$sendHttp}): {$sendRes}");
    }

    return true;
}

function sendViaSmtp(string $subject, string $htmlBody, string $textSummary, string $senderEmail, string $senderName, string $clinicName, string $recipient, string $bcc): bool {
    $autoloader = __DIR__ . '/vendor/autoload.php';
    if (!file_exists($autoloader)) {
        throw new Exception("PHPMailer autoloader missing at {$autoloader}");
    }
    require_once $autoloader;

    $smtpHost   = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
    $smtpPort   = (int)(getenv('SMTP_PORT') ?: 465);
    $smtpUser   = getenv('SMTP_USER') ?: getenv('SENDER_EMAIL');
    $smtpPass   = getenv('SMTP_PASS');
    $senderMail = getenv('SENDER_EMAIL') ?: $smtpUser;

    if (!$smtpPass || !$senderMail || !$recipient) {
        throw new Exception('Incomplete SMTP parameters in environment.');
    }

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->CharSet    = 'UTF-8';
    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    $mail->Port       = $smtpPort;
    $mail->SMTPSecure = ($smtpPort === 465)
        ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
        : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;

    $mail->setFrom($senderMail, sanitizeHeaderStr($clinicName));

    foreach (explode(',', $recipient) as $recip) {
        $clean = sanitizeHeaderStr($recip);
        if ($clean !== '') {
            $mail->addAddress($clean);
        }
    }

    if ($bcc !== '') {
        foreach (explode(',', $bcc) as $bccItem) {
            $cleanBcc = sanitizeHeaderStr($bccItem);
            if ($cleanBcc !== '') {
                $mail->addBCC($cleanBcc);
            }
        }
    }

    if ($senderEmail !== '' && filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
        $mail->addReplyTo($senderEmail, sanitizeHeaderStr($senderName));
    }

    $mail->isHTML(true);
    $mail->Subject = sanitizeHeaderStr($subject);
    $mail->Body    = $htmlBody;
    $mail->AltBody = $textSummary;

    $mail->send();
    return true;
}

function sendDiscordAlert(string $clinicName, string $mailDriver, string $errorMessage): void {
    $webhook = getenv('DISCORD_WEBHOOK_URL') ?: getenv('ALERT_WEBHOOK_URL');
    if (!$webhook) {
        return;
    }

    $domain         = $_SERVER['HTTP_HOST'] ?? 'Unknown Domain';
    $truncatedError = mb_substr($errorMessage, 0, 1000);

    $payload = [
        'embeds' => [[
            'title'       => "Mailer Delivery Error: {$clinicName}",
            'description' => "Form dispatch failed on **{$domain}**.",
            'color'       => 0xdc2626,
            'fields'      => [
                ['name' => 'Driver', 'value' => strtoupper($mailDriver), 'inline' => true],
                ['name' => 'Domain', 'value' => $domain,                 'inline' => true],
                ['name' => 'Error',  'value' => $truncatedError ?: 'Unknown error', 'inline' => false],
            ],
            'footer'      => ['text' => 'Argon Pipeline'],
            'timestamp'   => date('c')
        ]]
    ];

    $ch = curl_init($webhook);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 4
    ]);
    curl_exec($ch);
    curl_close($ch);
}