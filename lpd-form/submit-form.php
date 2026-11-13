<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// -----------------------------------------------------------------------------
// 1. Honeypot Check (Bot trap)
// -----------------------------------------------------------------------------
if (!empty($_POST['fax_number'])) {
    // Return fake success to bots without dispatching
    echo json_encode(['status' => 'success', 'message' => 'Your message has been sent successfully.']);
    exit;
}

// -----------------------------------------------------------------------------
// 2. Cloudflare Turnstile Verification
// -----------------------------------------------------------------------------
$turnstileSecret = getenv('TURNSTILE_SECRET_KEY') ?: '';
$turnstileToken  = $_POST['cf-turnstile-response'] ?? '';

if (!empty($turnstileSecret)) {
    if (empty($turnstileToken)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Turnstile verification failed: missing security token.']);
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
        error_log("Turnstile cURL error: " . $curlError);
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Unable to verify security challenge. Please try again.']);
        exit;
    }

    $verifyData = json_decode($verifyResult, true);
    if (!$verifyData || empty($verifyData['success'])) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Security challenge failed. Please refresh and try again.']);
        exit;
    }
}

// -----------------------------------------------------------------------------
// 3. PHI Consent Verification
// -----------------------------------------------------------------------------
if (empty($_POST['consent'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'You must accept the communication and PHI consent agreement to submit.']);
    exit;
}

// -----------------------------------------------------------------------------
// 4. Dynamic Field Extraction & Email Formatting
// -----------------------------------------------------------------------------
$clinicName   = getenv('CLINIC_NAME') ?: 'Argon Pipeline';
$formType     = trim($_POST['form_type'] ?? 'Website Inquiry');
$firstName    = trim($_POST['first_name'] ?? '');
$lastName     = trim($_POST['last_name'] ?? '');
$fullName     = trim($_POST['name'] ?? '');
$senderName   = trim("$firstName $lastName") ?: ($fullName ?: 'Website Visitor');
$senderEmail  = trim($_POST['email'] ?? '');
$senderPhone  = trim($_POST['phone'] ?? '');

$subject = "[{$clinicName}] New {$formType}: {$senderName}";

// Build dynamic field rows (ignoring system/internal keys)
$systemKeys = ['cf-turnstile-response', 'fax_number', 'consent', 'form_type'];
$tableRows   = '';
$textSummary = "NEW FORM SUBMISSION: {$clinicName}\nForm Type: {$formType}\n" . str_repeat('=', 40) . "\n\n";

foreach ($_POST as $key => $val) {
    if (in_array($key, $systemKeys, true)) {
        continue;
    }
    
    if (is_array($val)) {
        $cleanVal = implode(', ', array_map('trim', $val));
    } else {
        $cleanVal = trim((string)$val);
    }

    if ($cleanVal === '') {
        continue;
    }

    $label     = ucwords(str_replace(['_', '-'], ' ', $key));
    $safeLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
    $safeVal   = nl2br(htmlspecialchars($cleanVal, ENT_QUOTES, 'UTF-8'));

    $tableRows .= "
      <tr>
        <td style=\"padding: 10px 14px; font-weight: 600; color: #333; background: #fdfdfd; border-bottom: 1px solid #e2e8f0; width: 35%; vertical-align: top;\">{$safeLabel}</td>
        <td style=\"padding: 10px 14px; color: #111; border-bottom: 1px solid #e2e8f0; vertical-align: top;\">{$safeVal}</td>
      </tr>";

    $textSummary .= "{$label}: {$cleanVal}\n";
}

$submissionTime = date('F j, Y, g:i a e');
$clientIp       = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

$htmlBody = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{$subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #222; background: #f8fafc; margin: 0; padding: 24px;">
  <table role="presentation" style="max-width: 620px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; border-collapse: separate; border-spacing: 0; overflow: hidden; width: 100%;">
    <tr>
      <td style="background: #1a568c; padding: 18px 24px; color: #ffffff;">
        <h2 style="margin: 0; font-size: 19px; font-weight: 600;">{$clinicName}</h2>
        <div style="font-size: 13px; opacity: 0.9; margin-top: 2px;">New {$formType} Received</div>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 24px;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          {$tableRows}
        </table>
        
        <div style="margin-top: 24px; padding: 14px; background: #f1f5f9; border-radius: 4px; font-size: 11px; color: #475569; line-height: 1.4;">
          <strong>PHI Consent & Authorization:</strong> The sender acknowledged the risks of communicating via unencrypted communication channels and consented to receive email and phone communications regarding their care.<br>
          <strong>Submitted:</strong> {$submissionTime} | <strong>IP Address:</strong> {$clientIp}
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 12px 24px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
        Processed securely via <a href="https://argonpipeline.com" style="color: #1a568c; text-decoration: none;">Argon Pipeline</a>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

$textSummary .= "\n" . str_repeat('=', 40) . "\nConsent Accepted: Yes\nSubmitted: {$submissionTime}\nIP Address: {$clientIp}\n";

// -----------------------------------------------------------------------------
// 5. Mail Transport Selection & Dispatch
// -----------------------------------------------------------------------------
$mailDriver = strtolower(getenv('MAIL_DRIVER') ?: '');

// Auto-detect driver if not explicitly passed
if (empty($mailDriver)) {
    if (getenv('MS_CLIENT_ID') || getenv('MS_TENANT_ID')) {
        $mailDriver = 'graph';
    } else {
        $mailDriver = 'smtp';
    }
}

try {
    if ($mailDriver === 'graph') {
        sendViaGraph($subject, $htmlBody, $senderEmail, $senderName, $clinicName);
    } else {
        sendViaSmtp($subject, $htmlBody, $textSummary, $senderEmail, $senderName, $clinicName);
    }

    sendDiscordAlert($clinicName, $formType, $senderName, $senderEmail, $senderPhone);

    echo json_encode([
        'status'  => 'success',
        'message' => 'Thank you! Your inquiry has been securely delivered.'
    ]);
    exit;

} catch (Exception $e) {
    error_log("Dispatch error [{$mailDriver}]: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'status'  => 'error',
        'message' => 'An error occurred while transmitting your message. Please try again or contact our office directly.'
    ]);
    exit;
}

// -----------------------------------------------------------------------------
// Dispatch Handler: Microsoft Graph API (OAuth 2.0)
// -----------------------------------------------------------------------------
function sendViaGraph(string $subject, string $htmlBody, string $senderEmail, string $senderName, string $clinicName): bool {
    $tenantId     = getenv('MS_TENANT_ID');
    $clientId     = getenv('MS_CLIENT_ID');
    $clientSecret = getenv('MS_CLIENT_SECRET');
    $senderMail   = getenv('SENDER_EMAIL');
    $recipient    = getenv('RECIPIENT_EMAIL');
    $bcc          = getenv('BCC_EMAIL') ?: '';

    if (!$tenantId || !$clientId || !$clientSecret || !$senderMail || !$recipient) {
        throw new Exception("Incomplete Microsoft Graph credentials in environment.");
    }

    // Request OAuth2 Token
    $tokenUrl = "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token";
    $tokenFields = [
        'client_id'     => $clientId,
        'client_secret' => $clientSecret,
        'scope'         => 'https://graph.microsoft.com/.default',
        'grant_type'    => 'client_credentials'
    ];

    $ch = curl_init($tokenUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($tokenFields),
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

    $accessToken = $tokenData['access_token'];

    // Construct Payload
    $toRecipients = [];
    foreach (explode(',', $recipient) as $recip) {
        $clean = trim($recip);
        if ($clean !== '') {
            $toRecipients[] = ['emailAddress' => ['address' => $clean]];
        }
    }

    $message = [
        'subject'      => $subject,
        'body'         => [
            'contentType' => 'HTML',
            'content'     => $htmlBody
        ],
        'toRecipients' => $toRecipients
    ];

    if (!empty($bcc)) {
        $bccRecipients = [];
        foreach (explode(',', $bcc) as $bccItem) {
            $cleanBcc = trim($bccItem);
            if ($cleanBcc !== '') {
                $bccRecipients[] = ['emailAddress' => ['address' => $cleanBcc]];
            }
        }
        if (!empty($bccRecipients)) {
            $message['bccRecipients'] = $bccRecipients;
        }
    }

    if (!empty($senderEmail) && filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
        $message['replyTo'] = [
            [
                'emailAddress' => [
                    'address' => $senderEmail,
                    'name'    => $senderName
                ]
            ]
        ];
    }

    $sendUrl = "https://graph.microsoft.com/v1.0/users/" . urlencode($senderMail) . "/sendMail";
    $ch = curl_init($sendUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode(['message' => $message, 'saveToSentItems' => 'false']),
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $accessToken,
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

// -----------------------------------------------------------------------------
// Dispatch Handler: PHPMailer SMTP (Google Workspace / Standard SMTP)
// -----------------------------------------------------------------------------
function sendViaSmtp(string $subject, string $htmlBody, string $textSummary, string $senderEmail, string $senderName, string $clinicName): bool {
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
    $recipient  = getenv('RECIPIENT_EMAIL');
    $bcc        = getenv('BCC_EMAIL') ?: '';

    if (!$smtpPass || !$senderMail || !$recipient) {
        throw new Exception("Incomplete SMTP parameters in environment.");
    }

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    $mail->Port       = $smtpPort;
    $mail->SMTPSecure = ($smtpPort === 465)
        ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
        : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;

    $mail->setFrom($senderMail, $clinicName);

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

    if (!empty($senderEmail) && filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
        $mail->addReplyTo($senderEmail, $senderName);
    }

    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body    = $htmlBody;
    $mail->AltBody = $textSummary;

    $mail->send();
    return true;
}

// -----------------------------------------------------------------------------
// Optional Discord Operational Webhook
// -----------------------------------------------------------------------------
function sendDiscordAlert(string $clinicName, string $formType, string $senderName, string $senderEmail, string $senderPhone): void {
    $webhook = getenv('DISCORD_WEBHOOK_URL');
    if (!$webhook) {
        return;
    }

    $payload = [
        'embeds' => [[
            'title'       => "New Form Submission: {$clinicName}",
            'description' => "Received new **{$formType}**.",
            'color'       => 0x1a568c,
            'fields'      => [
                ['name' => 'Name',  'value' => $senderName ?: 'Not specified',  'inline' => true],
                ['name' => 'Email', 'value' => $senderEmail ?: 'Not specified', 'inline' => true],
                ['name' => 'Phone', 'value' => $senderPhone ?: 'Not specified', 'inline' => true],
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
