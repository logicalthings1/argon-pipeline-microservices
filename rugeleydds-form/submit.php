<?php
require_once 'config.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed.']);
    exit;
}

if (!empty($_POST['fax_number'])) {
    echo json_encode(['success' => true]);
    exit;
}

if (empty($_POST['consent']) || $_POST['consent'] !== 'yes') {
    echo json_encode(['success' => false, 'error' => 'You must acknowledge the non-PHI administrative terms.']);
    exit;
}

$turnstileToken = $_POST['cf-turnstile-response'] ?? '';
if (empty($turnstileToken) && TURNSTILE_SECRET_KEY !== 'PLACEHOLDER_TURNSTILE_SECRET_KEY') {
    echo json_encode(['success' => false, 'error' => 'Please complete the security verification challenge.']);
    exit;
}

if (TURNSTILE_SECRET_KEY !== 'PLACEHOLDER_TURNSTILE_SECRET_KEY') {
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret' => TURNSTILE_SECRET_KEY,
        'response' => $turnstileToken,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
    ]));
    $turnstileRes = curl_exec($ch);
    curl_close($ch);
    $turnstileData = json_decode($turnstileRes, true);

    if (empty($turnstileData) || !$turnstileData['success']) {
        echo json_encode(['success' => false, 'error' => 'Security challenge validation failed. Please try again.']);
        exit;
    }
}

$formType = $_POST['form_type'] ?? 'contact';
$name = htmlspecialchars(trim($_POST['name'] ?? ''));
$email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
$phone = htmlspecialchars(trim($_POST['phone'] ?? ''));

if (!$name || !$email || !$phone) {
    echo json_encode(['success' => false, 'error' => 'Please provide your name, valid email, and phone number.']);
    exit;
}

if ($formType === 'appointment') {
    $subject = "Online Appointment Request: {$name}";
    $patientType = htmlspecialchars(trim($_POST['patient_type'] ?? 'Not specified'));
    $dates = htmlspecialchars(trim($_POST['preferred_dates'] ?? ''));
    $times = htmlspecialchars(trim($_POST['preferred_times'] ?? ''));
    $reason = nl2br(htmlspecialchars(trim($_POST['reason'] ?? '')));

    $bodyHtml = "
    <h2>New Appointment Request</h2>
    <p><strong>Patient Name:</strong> {$name}</p>
    <p><strong>Email:</strong> {$email}</p>
    <p><strong>Phone:</strong> {$phone}</p>
    <p><strong>Patient Status:</strong> {$patientType}</p>
    <p><strong>Preferred Dates:</strong> {$dates}</p>
    <p><strong>Preferred Times:</strong> {$times}</p>
    <p><strong>Reason for Visit:</strong><br>{$reason}</p>
    <hr>
    <p><small>Submitted via rugeleydds.com appointment form on " . date('Y-m-d H:i:s T') . "</small></p>";
} else {
    $subject = "Website Contact Message: {$name}";
    $message = nl2br(htmlspecialchars(trim($_POST['message'] ?? '')));

    $bodyHtml = "
    <h2>New Website Inquiry</h2>
    <p><strong>Name:</strong> {$name}</p>
    <p><strong>Email:</strong> {$email}</p>
    <p><strong>Phone:</strong> {$phone}</p>
    <p><strong>Message:</strong><br>{$message}</p>
    <hr>
    <p><small>Submitted via rugeleydds.com contact form on " . date('Y-m-d H:i:s T') . "</small></p>";
}

if (MS_CLIENT_ID === 'PLACEHOLDER_CLIENT_ID' || MS_TENANT_ID === 'PLACEHOLDER_TENANT_ID') {
    echo json_encode(['success' => true, 'note' => 'Staging mock dispatch']);
    exit;
}

$tokenUrl = "https://login.microsoftonline.com/" . MS_TENANT_ID . "/oauth2/v2.0/token";
$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'client_id' => MS_CLIENT_ID,
    'client_secret' => MS_CLIENT_SECRET,
    'scope' => 'https://graph.microsoft.com/.default',
    'grant_type' => 'client_credentials'
]));
$tokenRes = curl_exec($ch);
curl_close($ch);
$tokenData = json_decode($tokenRes, true);

if (empty($tokenData['access_token'])) {
    error_log("Graph API Auth Failed: " . $tokenRes);
    echo json_encode(['success' => false, 'error' => 'Internal email authentication error.']);
    exit;
}
$accessToken = $tokenData['access_token'];

$toRecipients = array_map(function($addr) {
    return ['emailAddress' => ['address' => $addr]];
}, RECIPIENTS_TO);

$bccRecipients = array_map(function($addr) {
    return ['emailAddress' => ['address' => $addr]];
}, RECIPIENTS_BCC);

$payload = [
    'message' => [
        'subject' => $subject,
        'body' => [
            'contentType' => 'HTML',
            'content' => $bodyHtml
        ],
        'toRecipients' => $toRecipients,
        'bccRecipients' => $bccRecipients
    ],
    'saveToSentItems' => 'true'
];

$sendUrl = "https://graph.microsoft.com/v1.0/users/" . urlencode(MS_SENDER_EMAIL) . "/sendMail";
$ch = curl_init($sendUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $accessToken,
    'Content-Type: application/json'
]);
$sendRes = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode === 202) {
    echo json_encode(['success' => true]);
} else {
    error_log("Graph API sendMail error [HTTP {$httpCode}]: " . $sendRes);
    echo json_encode(['success' => false, 'error' => 'Failed to dispatch email via office mailbox.']);
}
