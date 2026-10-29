<?php require_once 'config.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contact Us - John K Rugeley, DDS</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 16px; color: #333; background: #fff; }
    .form-container { max-width: 600px; margin: 0 auto; }
    .form-group { margin-bottom: 16px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; }
    .required { color: #d32f2f; }
    input[type="text"], input[type="email"], input[type="tel"], textarea {
      width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 15px;
    }
    textarea { height: 120px; resize: vertical; }
    .consent-group { display: flex; align-items: flex-start; gap: 10px; margin: 20px 0; font-size: 13px; color: #555; }
    .consent-group input { margin-top: 3px; }
    .btn-submit { background-color: #1a568c; color: #fff; border: none; padding: 12px 24px; font-size: 16px; font-weight: 600; border-radius: 4px; cursor: pointer; width: 100%; }
    .btn-submit:hover { background-color: #13426b; }
    .btn-submit:disabled { background-color: #a0b2c6; cursor: not-allowed; }
    .honeypot { position: absolute; left: -5000px; }
    #success-message { display: none; background: #e8f5e9; border: 1px solid #a5d6a7; color: #2e7d32; padding: 20px; border-radius: 4px; text-align: center; }
    #error-message { display: none; background: #ffebee; border: 1px solid #ffcdd2; color: #c62828; padding: 12px; border-radius: 4px; margin-bottom: 16px; }
  </style>
</head>
<body>
<div class="form-container">
  <div id="error-message"></div>
  <div id="success-message" tabindex="-1">
    <h3>Thank you!</h3>
    <p>Your message has been securely sent to our front desk team. We will be in touch shortly.</p>
  </div>

  <form id="contact-form" action="submit.php" method="POST">
    <input type="hidden" name="form_type" value="contact">

    <div class="honeypot" aria-hidden="true">
      <input type="text" name="fax_number" tabindex="-1" autocomplete="off">
    </div>

    <div class="form-group">
      <label for="name">Your Name <span class="required">*</span></label>
      <input type="text" id="name" name="name" required>
    </div>

    <div class="form-group">
      <label for="email">Your Email <span class="required">*</span></label>
      <input type="email" id="email" name="email" required>
    </div>

    <div class="form-group">
      <label for="phone">Your Phone <span class="required">*</span></label>
      <input type="tel" id="phone" name="phone" required>
    </div>

    <div class="form-group">
      <label for="message">Your Message <span class="required">*</span></label>
      <textarea id="message" name="message" required></textarea>
    </div>

    <div class="consent-group">
      <input type="checkbox" id="consent" name="consent" value="yes" required>
      <label for="consent">
        <strong>This Form Is Not For Submitting Personal Health Information</strong><br>
        I acknowledge that this form is strictly for general administrative inquiries and scheduling requests and is not intended for clinical symptoms, medical/dental histories, or sensitive health details. <span class="required">*</span>
      </label>
    </div>

    <div class="form-group">
      <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars(TURNSTILE_SITE_KEY); ?>"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Send Message</button>
  </form>
</div>

<script>
document.getElementById('contact-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const errorDiv = document.getElementById('error-message');
  const successDiv = document.getElementById('success-message');

  errorDiv.style.display = 'none';
  btn.disabled = true;
  btn.innerText = 'Sending...';

  try {
    const formData = new FormData(this);
    const res = await fetch('submit.php', { method: 'POST', body: formData });
    const data = await res.json();

    if (data.success) {
      document.getElementById('contact-form').style.display = 'none';
      successDiv.style.display = 'block';
      window.scrollTo({ top: 0, behavior: 'smooth' });
      successDiv.focus();
      window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
    } else {
      errorDiv.innerText = data.error || 'An error occurred while submitting. Please call our office at 512-343-2758.';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btn.innerText = 'Send Message';
    }
  } catch (err) {
    errorDiv.innerText = 'Unable to send message right now. Please call our office at 512-343-2758.';
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btn.innerText = 'Send Message';
  }
});
</script>
</body>
</html>
