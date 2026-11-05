<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.argonpipeline.com;https://argonpipeline.com';

// 2. Robust regex split: handles BOTH commas and semicolons gracefully
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

// 3. Clean and join them up with spaces for the CSP string
$cspOrigins = implode(' ', array_filter(array_unique($allowed_origins)));

// 4. Send the browser-approved header
header("Content-Security-Policy: frame-ancestors 'self' " . $cspOrigins . ";");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Argon Pipeline Contact Form</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Figtree:ital,wght@0,300..900;1,300..900&display=swap" rel="stylesheet">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: Figtree, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 12px;
      color: #222;
      background: #fff;
    }
    .form-container {
      max-width: 600px;
      margin: 0;
    }

    /* Strict 2-Column Row (Desktop and Mobile) */
    .form-row {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
    }
    .form-col {
      flex: 1 1 0;
      min-width: 0;
    }
    .form-full {
      width: 100%;
      margin-bottom: 12px;
    }

    label {
      display: block;
      font-size: 0.95rem;
      font-weight: 500;
      margin-bottom: 5px;
      color: #111;
    }
    .required {
      color: #d32f2f;
      font-weight: bold;
    }

    input[type="text"], input[type="email"], select, textarea {
      font-family: Figtree, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 1rem;
      font-weight: 500;
      width: 100%;
      padding: 9px 11px;
      border: 1px solid #bbbbbb;
      border-radius: 4px;
      color: #111;
      background-color: #fff;
    }
    textarea {
      height: 95px;
      resize: vertical;
    }

    /* WCAG Focus Indicators */
    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible {
      outline: 2px solid #554F9B;
      outline-offset: 1px;
    }

    /* Pill Submit Button */
    .btn-submit {
      border-radius: 30px;
      background: #554F9B;
      color: #ffffff;
      padding: 0.5em 1.4em;
      border: 0;
      font-size: 1.15rem;
      font-weight: 400;
      line-height: 1.6;
      display: inline-block;
      font-family: Figtree, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      cursor: pointer;
      transition: background 0.2s ease;
      margin-top: 8px;
    }
    .btn-submit:hover {
      background: #807AAF;
    }
    .btn-submit:disabled {
      background: #9994c4;
      cursor: not-allowed;
    }

    .honeypot {
      display: none !important;
    }

    #success-message {
      display: none;
      background-color: #e8f5e9;
      color: #2e7d32;
      border: 1px solid #c8e6c9;
      padding: 20px;
      border-radius: 4px;
      text-align: left;
      max-width: 600px;
      margin: 0;
    }
  </style>
</head>
<body>

<main class="form-container">
  <div id="success-message" role="status" aria-live="polite" tabindex="-1">
    <h3 style="margin-top: 0;">Message Sent Securely</h3>
    <p style="margin-bottom: 0;">Thank you! Your secure message has been received. We will get back to you shortly.</p>
  </div>
  
  <form id="argon-secure-form" novalidate aria-label="Argon Pipeline Contact Form">
    <!-- Honeypot -->
    <div class="honeypot" aria-hidden="true">
      <input type="text" id="fax_number" name="fax_number" tabindex="-1" autocomplete="off">
    </div>

    <!-- Row 1: First Name & Last Name -->
    <div class="form-row">
      <div class="form-col">
        <label for="first_name">First Name <span class="required" aria-hidden="true">*</span></label>
        <input type="text" id="first_name" name="first_name" autocomplete="given-name" required aria-required="true">
      </div>
      <div class="form-col">
        <label for="last_name">Last Name <span class="required" aria-hidden="true">*</span></label>
        <input type="text" id="last_name" name="last_name" autocomplete="family-name" required aria-required="true">
      </div>
    </div>

    <!-- Row 2: Email & Website URL -->
    <div class="form-row">
      <div class="form-col">
        <label for="email">Email Address <span class="required" aria-hidden="true">*</span></label>
        <input type="email" id="email" name="email" autocomplete="email" required aria-required="true">
      </div>
      <div class="form-col">
        <label for="url">Website URL <span class="required" aria-hidden="true">*</span></label>
        <input type="text" id="url" name="url" required aria-required="true">
      </div>
    </div>

    <!-- Row 3: Current Suite & Specify Other -->
    <div class="form-row">
      <div class="form-col">
        <label for="service">Your Current Email/Office Suite <span class="required" aria-hidden="true">*</span></label>
        <select id="service" name="service" required aria-required="true">
          <option value="" disabled selected hidden>Select...</option>
          <option value="google">Google Workspace</option>
          <option value="microsoft">Microsoft 365</option>
          <option value="other">Other</option>
        </select>
      </div>
      <div class="form-col">
        <label for="specify_other">Specify Other</label>
        <input type="text" id="specify_other" name="specify_other" placeholder="If other, please specify">
      </div>
    </div>

    <!-- Row 4: Message (Full Width) -->
    <div class="form-full">
      <label for="message">Question or Comment <span class="required" aria-hidden="true">*</span></label>
      <textarea id="message" name="message" required aria-required="true"></textarea>
    </div>
    
    <!-- Turnstile (Light Theme) -->
    <div class="form-full">
      <div class="cf-turnstile" data-sitekey="0x4AAAAAAETIrCfMZKCInxXw" data-theme="light"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Send Message</button>
  </form>
</main>

<script>
document.getElementById('argon-secure-form').addEventListener('submit', async function(e) {
  e.preventDefault();

  const form = e.target;
  const btn = document.getElementById('submit-btn');
  const originalBtnText = btn ? btn.innerText : 'Send Message';

  if (btn) {
    btn.disabled = true;
    btn.innerText = 'Securing connection...';
  }

  try {
    const formData = new FormData(form);
    const formObject = Object.fromEntries(formData.entries());

    const submitResponse = await fetch('submit-form.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formObject)
    });

    const res = await submitResponse.json();

    if (submitResponse.ok && (res.status === 'success' || res.success === true)) {
      form.style.display = 'none';
      const successDiv = document.getElementById('success-message');
      if (successDiv) {
        successDiv.style.display = 'block';
        window.scrollTo({ top: 0, behavior: 'smooth' });
        successDiv.focus();
      }

      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
      }

      form.reset();
    } else {
      alert(res.message || 'Your submission failed. Please contact info@argonpipeline.com.');
      console.error('Server Debug Info:', res);
      if (typeof turnstile !== 'undefined') turnstile.reset();
    }

  } catch (error) {
    alert('A secure connection error occurred. Please try again.');
    console.error('Frontend Error Tracking:', error);
    if (typeof turnstile !== 'undefined') turnstile.reset();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = originalBtnText;
    }
  }
});
</script>

</body>
</html>
