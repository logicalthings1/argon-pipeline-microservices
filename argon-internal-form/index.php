<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.argonpipeline.com;https://argonpipeline.com';

// 2. Robust regex split: handles BOTH commas and semicolons gracefully
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

// 3. Clean and join them up with spaces for the CSP string
$cspOrigins = implode(' ', array_filter(array_unique($allowed_origins)));

// 4. Send the perfect, browser-approved header
header("Content-Security-Policy: frame-ancestors 'self' " . $cspOrigins . ";");
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Argon Pipeline Contact Form</title>
  <style>
    form, div {font-family: Figtree, Helvetica, Arial, sans-serif;}
    .field-container {margin-bottom: 15px;}
    label {display:block; font-size:1rem; font-weight:500; margin-bottom: 5px;}
    input, select, textarea {font-size:1rem; font-weight:500; width:100%; padding:10px; box-sizing:border-box; border:solid #bbbbbb 1px; border-radius: 2px;}
    button, input[type=button], input[type=reset], input[type=submit] {
      border-radius: 30px;
      background: #554F9B;
      color: #ffffff;
      padding: .4em 1em;
      border: 0;
      font-size: 1.125rem;
      line-height: 1.6;
      display: inline-block;
      font-family: Figtree, Helvetica, Arial, sans-serif;
      cursor: pointer;
      text-decoration: none;
      transition: all .2s ease;
      box-shadow: 0px 0px 0px -7px rgba(0, 0, 0, 0);
      margin-top: 15px;
    }
    button:hover {background: #807AAF;}
    .required {color: red; font-weight: bold;}
  </style>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>

<body>

<!-- ACCESSIBLE SUCCESS MESSAGE -->
<div id="success-message" role="status" aria-live="polite" tabindex="-1" style="display: none; background-color: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; padding: 25px; border-radius: 4px; text-align: center; max-width: 500px; margin: 0 auto;">
    <h3 style="margin-top: 0;">Message Sent Securely</h3>
    <p style="margin-bottom: 0;">Thank you! Your secure message has been received. We will get back to you shortly.</p>
</div>
	
<form id="argon-secure-form" style="max-width: 500px; margin: 0 auto;">

  <!-- "fax number" -->
  <div style="position: absolute; left: -5000px;" aria-hidden="true">
    <label for="fax_number">Leave this field blank</label>
    <input type="text" id="fax_number" name="fax_number" tabindex="-1" autocomplete="off">
  </div>
  
  <div class="field-container">
    <label for="first_name">First Name <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="first_name" name="first_name" autocomplete="given-name" required>
  </div>

  <div class="field-container">
    <label for="last_name">Last Name <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="last_name" name="last_name" autocomplete="family-name" required>
  </div>

  <div class="field-container">
    <label for="email">Email Address <span class="required" aria-hidden="true">*</span></label>
    <input type="email" id="email" name="email" autocomplete="email" required>
  </div>

  <div class="field-container">
    <label for="url">Website URL <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="url" name="url" required>
  </div>

  <div class="field-container">
    <label for="service">Your Current Email/Office Suite <span class="required" aria-hidden="true">*</span></label>
    <select id="service" name="service" required>
      <option value="" disabled selected hidden>Select...</option>
      <option value="google">Google Workspace</option>
      <option value="microsoft">Microsoft 365</option>
      <option value="other">Other</option>
    </select>
  </div>

  <div class="field-container">
    <label for="message">Question or Comment <span class="required" aria-hidden="true">*</span></label>
    <textarea id="message" name="message" rows="5" required></textarea>
  </div>
  
  <div class="cf-turnstile" data-sitekey="0x4AAAAAAETIrCfMZKCInxXw" data-theme="light"></div>

  <button type="submit" id="submit-btn">Send Message</button>
</form>

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

        const submitResponse = await fetch('/submit-form.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formObject)
        });

        const res = await submitResponse.json();

        if (submitResponse.ok && res.status === 'success') {
            // 1. Hide form and reveal success message
            form.style.display = 'none';
            const successDiv = document.getElementById('success-message');
            if (successDiv) {
                successDiv.style.display = 'block';

                // 2. Smoothly snap iframe viewport to top
                window.scrollTo({ top: 0, behavior: 'smooth' });

                // 3. Move accessibility focus to confirmation box
                successDiv.focus();
            }

            // 4. Instruct parent window to scroll iframe into view if embedded
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
            }

            // 5. Reset form fields
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