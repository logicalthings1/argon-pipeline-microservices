<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contact Us - {{CLINIC_NAME}}</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 12px;
      color: #222;
      background: #fff;
    }
    .form-container {
      max-width: 600px;
      margin: 0;
    }
    
    .form-row {
      display: flex;
      gap: 12px;
      margin-bottom: 10px;
    }
    .form-col {
      flex: 1 1 0;
      min-width: 0;
    }
    .form-full {
      width: 100%;
      margin-bottom: 10px;
    }

    label {
      display: block;
      font-weight: 600;
      margin-bottom: 4px;
      font-size: 13px;
      color: #111;
    }
    .required {
      color: #d32f2f;
      font-weight: bold;
    }
    
    input[type="text"], input[type="email"], input[type="tel"], select, textarea {
      width: 100%;
      padding: 8px 10px;
      border: 1px solid #767676;
      border-radius: 4px;
      font-size: 14px;
      color: #111;
      background-color: #fff;
      font-family: inherit;
    }
    textarea {
      height: 70px;
      resize: vertical;
    }

    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible {
      outline: 2px solid #1a568c;
      outline-offset: 1px;
    }

    .consent-group {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      margin: 10px 0 14px 0;
      font-size: 12px;
      line-height: 1.4;
      color: #333;
    }
    .consent-group input[type="checkbox"] {
      width: 18px;
      height: 18px;
      margin-top: 1px;
      flex-shrink: 0;
      accent-color: #1a568c;
      cursor: pointer;
    }
    .consent-group label {
      font-weight: normal;
      cursor: pointer;
      margin: 0;
    }

    .btn-submit {
      background-color: #1a568c;
      color: #fff;
      border: none;
      padding: 11px 20px;
      font-size: 15px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      width: 100%;
    }
    .btn-submit:hover {
      background-color: #13426b;
    }
    .btn-submit:disabled {
      background-color: #728496;
      cursor: not-allowed;
    }

    .honeypot {
      display: none !important;
    }

    #success-message {
      display: none;
      background: #e8f5e9;
      border: 2px solid #2e7d32;
      color: #1b5e20;
      padding: 16px;
      border-radius: 4px;
      text-align: left;
    }
    #error-message {
      display: none;
      background: #ffebee;
      border: 2px solid #c62828;
      color: #b71c1c;
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 12px;
      font-size: 13px;
      line-height: 1.4;
    }

    .attribution {
      text-align: left;
      margin: 12px 0 0 0;
      color: #0a0a0a;
      font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, "Helvetica Neue", Arial, sans-serif;
      font-size: 11px;
      line-height: 1.8em;
      font-weight: 400;
      -webkit-font-smoothing: antialiased;
      font-style: normal;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .attribution a {
      color: #555;
      text-decoration: none;
    }
    .attribution a:hover, .attribution a:focus-visible {
      color: #1a568c;
      text-decoration: underline;
    }
  </style>
</head>
<body>
<main class="form-container">
  <div id="error-message" role="alert" aria-live="assertive"></div>
  <div id="success-message" role="status" aria-live="polite" tabindex="-1">
    <h3 style="margin-top: 0;">Thank you!</h3>
    <p>Your message has been securely sent to our front desk team. We will be in touch shortly.</p>
  </div>

  <form id="contact-form" action="submit-form.php" method="POST" novalidate aria-label="Contact Us Form">
    <div class="honeypot" aria-hidden="true">
      <input type="text" name="fax_number" tabindex="-1" autocomplete="off">
    </div>

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

    <div class="form-row">
      <div class="form-col">
        <label for="email">Email <span class="required" aria-hidden="true">*</span></label>
        <input type="email" id="email" name="email" autocomplete="email" required aria-required="true">
      </div>
      <div class="form-col">
        <label for="phone">Phone <span class="required" aria-hidden="true">*</span></label>
        <input type="tel" id="phone" name="phone" autocomplete="tel" required aria-required="true">
      </div>
    </div>

    <div class="form-row">
      <div class="form-col">
        <label for="how_you_find">How did you find us? <span class="required" aria-hidden="true">*</span></label>
        <select id="how_you_find" name="how_you_find" required aria-required="true">
          <option value="" disabled selected>Please select</option>
          <option value="Google">Google / Search</option>
          <option value="AI/ChatGPT/Gemini">AI / ChatGPT / Gemini</option>
          <option value="Insurance">Insurance Provider</option>
          <option value="Friend/Family">Friend / Family</option>
          <option value="Other">Referral / Other</option>
        </select>
      </div>
      <div class="form-col">
        <label for="referal_name">Referral / Other Details</label>
        <input type="text" id="referal_name" name="referal_name" placeholder="Name or source">
      </div>
    </div>

    <div class="form-full">
      <label for="message">Message <span class="required" aria-hidden="true">*</span></label>
      <textarea id="message" name="message" required aria-required="true"></textarea>
    </div>

    <div class="consent-group">
      <input type="checkbox" id="consent" name="consent" value="yes" required aria-required="true">
      <label for="consent">
        By checking this box and submitting this form, I consent to the collection and processing of the information provided, which may include Protected Health Information (PHI). I authorize this practice to contact me via email, phone, text message, or voicemail. I acknowledge and understand that standard email and text messaging are not secure or encrypted methods of communication. I accept the risks of communicating via unencrypted email and text message (including the risk of unauthorized access or interception by third parties) and explicitly request and consent to receive email and text communications from this practice regarding my inquiry or care. <span class="required" aria-hidden="true">*</span>
      </label>
    </div>

    <div class="form-full">
      <div class="cf-turnstile" data-theme="light" data-sitekey="<?= htmlspecialchars(getenv('TURNSTILE_SITE_KEY') ?: '', ENT_QUOTES, 'UTF-8') ?>"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Send Message</button>

    <p class="attribution">
      <a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign={{CLINIC_SLUG}}" target="_blank" rel="noopener">HIPAA Compliant Contact Form</a>
    </p>
  </form>
</main>

<script>
document.getElementById('contact-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const form = this;
  const btn = document.getElementById('submit-btn');
  const errorDiv = document.getElementById('error-message');
  const successDiv = document.getElementById('success-message');

  if (!form.checkValidity()) {
    errorDiv.innerText = 'Please complete all required fields and accept the consent agreement before submitting.';
    errorDiv.style.display = 'block';
    errorDiv.focus();
    return;
  }

  errorDiv.style.display = 'none';
  btn.disabled = true;
  btn.innerText = 'Sending...';

  try {
    const formData = new FormData(form);
    const res = await fetch('submit-form.php', { 
      method: 'POST', 
      headers: { 'Accept': 'application/json' },
      body: formData 
    });
    const data = await res.json();

    if (data.status === 'success' || data.success === true) {
      form.style.display = 'none';
      successDiv.style.display = 'block';
      successDiv.focus();
      window.scrollTo({ top: 0, behavior: 'smooth' });
      window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
    } else {
      errorDiv.innerText = data.message || data.error || 'An error occurred while submitting.';
      errorDiv.style.display = 'block';
      errorDiv.focus();
      btn.disabled = false;
      btn.innerText = 'Send Message';
      if (window.turnstile && typeof window.turnstile.reset === 'function') {
        window.turnstile.reset();
      }
    }
  } catch (err) {
    errorDiv.innerText = 'Unable to send message right now. Please try again.';
    errorDiv.style.display = 'block';
    errorDiv.focus();
    btn.disabled = false;
    btn.innerText = 'Send Message';
    if (window.turnstile && typeof window.turnstile.reset === 'function') {
      window.turnstile.reset();
    }
  }
});
</script>
</body>
</html>
