<?php
$allowed_origins = [
    'https://rugeleydds.com',
    'https://www.rugeleydds.com'
];
$cspOrigins = implode(' ', $allowed_origins);
header("Content-Security-Policy: frame-ancestors 'self' {$cspOrigins};");

define('RECIPIENTS_TO', [
    'reception@rugeleydds.com',
    'busmgr@rugeleydds.com'
]);
define('RECIPIENTS_BCC', [
    'art@logicalthings.com'
]);

define('MS_TENANT_ID', getenv('MS_TENANT_ID') ?: 'PLACEHOLDER_TENANT_ID');
define('MS_CLIENT_ID', getenv('MS_CLIENT_ID') ?: 'PLACEHOLDER_CLIENT_ID');
define('MS_CLIENT_SECRET', getenv('MS_CLIENT_SECRET') ?: 'PLACEHOLDER_CLIENT_SECRET');
define('MS_SENDER_EMAIL', getenv('MS_SENDER_EMAIL') ?: 'reception@rugeleydds.com');

define('TURNSTILE_SITE_KEY', getenv('TURNSTILE_SITE_KEY') ?: 'PLACEHOLDER_TURNSTILE_SITE_KEY');
define('TURNSTILE_SECRET_KEY', getenv('TURNSTILE_SECRET_KEY') ?: 'PLACEHOLDER_TURNSTILE_SECRET_KEY');
