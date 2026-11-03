<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Make an Appointment - John K Rugeley, DDS</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 16px; color: #222; background: #fff; }
    .form-container { max-width: 600px; margin: 0 auto; }
    .required-notice { font-size: 13px; color: #555; margin-bottom: 18px; }
    .form-group { margin-bottom: 18px; }
    label, legend { display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; color: #111; }
    .required { color: #d32f2f; font-weight: bold; }
    
    input[type="text"], input[type="email"], input[type="tel"], select, textarea {
      width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid #767676; border-radius: 4px; font-size: 16px; color: #111; background-color: #fff;
    }
    textarea { height: 110px; resize: vertical; }

    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible {
      outline: 3px solid #1a568c;
      outline-offset: 2px;
    }

    fieldset.radio-fieldset {
      border: none;
      padding: 0;
      margin: 0;
    }
    .radio-group { display: flex; gap: 24px; margin-top: 6px; }
    .radio-group label { font-weight: normal; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; min-height: 32px; }
    .radio-group input[type="radio"] { width: 18px; height: 18px; margin: 0; accent-color: #1a568c; }

    .consent-group { display: flex; align-items: flex-start; gap: 12px; margin: 22px 0; font-size: 13.5px; line-height: 1.5; color: #333; }
    .consent-group input[type="checkbox"] { width: 20px; height: 20px; margin-top: 2px; flex-shrink: 0; accent-color: #1a568c; cursor: pointer; }
    .consent-group label { font-weight: normal; cursor: pointer; margin: 0; }

    .btn-submit { background-color: #1a568c; color: #fff; border: none; padding: 14px 24px; font-size: 16px; font-weight: 600; border-radius: 4px; cursor: pointer; width: 100%; min-height: 48px; }
    .btn-submit:hover { background-color: #13426b; }
    .btn-submit:disabled { background-color: #728496; cursor: not-allowed; }

    .honeypot { display: none !important; }

    #success-message { display: none; background: #e8f5e9; border: 2px solid #2e7d32; color: #1b5e20; padding: 20px; border-radius: 4px; text-align: center; }
    #error-message { display: none; background: #ffebee; border: 2px solid #c62828; color: #b71c1c; padding: 14px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; line-height: 1.4; }

    .attribution {
      text-align: center;
      margin: 14px 0 0 0;
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
    <h2>Appointment Request Received</h2>
    <p>Thank you! Our scheduling coordinator will review your requested dates and contact you to confirm your visit.</p>
  </div>

  <form id="appointment-form" action="submit-form.php" method="POST" novalidate aria-label="Appointment Request Form">
    <input type="hidden" name="form_type" value="appointment">
    <p class="required-notice"><span class="required" aria-hidden="true">*</span> Indicates required fields</p>

    <div class="honeypot" aria-hidden="true">
      <input type="text" name="fax_number" tabindex="-1" autocomplete="off">
    </div>

    <div class="form-group">
      <label for="name">Your Name <span class="required" aria-hidden="true">*</span></label>
      <input type="text" id="name" name="name" autocomplete="name" required aria-required="true">
    </div>

    <div class="form-group">
      <label for="email">Your Email <span class="required" aria-hidden="true">*</span></label>
      <input type="email" id="email" name="email" autocomplete="email" required aria-required="true">
    </div>

    <div class="form-group">
      <label for="phone">Your Phone <span class="required" aria-hidden="true">*</span></label>
      <input type="tel" id="phone" name="phone" autocomplete="tel" required aria-required="true">
    </div>

    <div class="form-group">
      <fieldset class="radio-fieldset">
        <legend>Patient Type <span class="required" aria-hidden="true">*</span></legend>
        <div class="radio-group">
          <label><input type="radio" name="patient_type" value="Current Patient" required aria-required="true"> Current Patient</label>
          <label><input type="radio" name="patient_type" value="New Patient" required aria-required="true"> New Patient</label>
        </div>
      </fieldset>
    </div>

    <div class="form-group">
      <label for="preferred_dates">Preferred Dates <span class="required" aria-hidden="true">*</span></label>
      <input type="text" id="preferred_dates" name="preferred_dates" placeholder="e.g. Next Tuesday or Thursday" required aria-required="true">
    </div>

    <div class="form-group">
      <label for="preferred_times">Preferred Times <span class="required" aria-hidden="true">*</span></label>
      <input type="text" id="preferred_times" name="preferred_times" placeholder="e.g. Morning (8am - 12pm) or After 2pm" required aria-required="true">
    </div>

    <div class="form-group">
      <label for="how_you_find">How did you find us? <span class="required" aria-hidden="true">*</span></label>
      <select id="how_you_find" name="how_you_find" required aria-required="true">
        <option value="" disabled selected>Please select an option</option>
        <option value="Google">Google / Search</option>
        <option value="AI/ChatGPT/Gemini">AI / ChatGPT / Gemini</option>
        <option value="Insurance">Insurance Provider</option>
        <option value="Friend/Family">Friend / Family</option>
        <option value="Other">Referral / Other</option>
      </select>
    </div>

    <div class="form-group">
      <label for="referal_name">Referral / Other Details</label>
      <input type="text" id="referal_name" name="referal_name" placeholder="Name or source">
    </div>

    <div class="form-group">
      <label for="reason">Please describe your reason for visiting Dr. Rugeley <span class="required" aria-hidden="true">*</span></label>
      <textarea id="reason" name="reason" placeholder="e.g. Routine cleaning and checkup, tooth pain, consultation" required aria-required="true"></textarea>
    </div>

    <div class="consent-group">
      <input type="checkbox" id="consent" name="consent" value="yes" required aria-required="true">
      <label for="consent">
        By checking this box and submitting this form, I consent to the collection and processing of the information provided, which may include Protected Health Information (PHI). I authorize this practice to contact me via email, phone, text message, or voicemail. I acknowledge and understand that standard email and text messaging are not secure or encrypted methods of communication. I accept the risks of communicating via unencrypted email and text message (including the risk of unauthorized access or interception by third parties) and explicitly request and consent to receive email and text communications from this practice regarding my inquiry or care. <span class="required" aria-hidden="true">*</span>
      </label>
    </div>

    <div class="form-group">
      <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(getenv('TURNSTILE_SITE_KEY') ?: '', ENT_QUOTES, 'UTF-8') ?>"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Request Appointment</button>

    <p class="attribution">
      <a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign=rugeleydds" target="_blank" rel="noopener">HIPAA Compliant Contact Form</a>
    </p>
  </form>
</main>

<script>
document.getElementById('appointment-form').addEventListener('submit', async function(e) {
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
  btn.innerText = 'Submitting Request...';

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
      errorDiv.innerText = data.message || data.error || 'An error occurred while submitting. Please call our office at 512-343-2758.';
      errorDiv.style.display = 'block';
      errorDiv.focus();
      btn.disabled = false;
      btn.innerText = 'Request Appointment';
      if (window.turnstile && typeof window.turnstile.reset === 'function') {
        window.turnstile.reset();
      }
    }
  } catch (err) {
    errorDiv.innerText = 'Unable to send appointment request. Please call our office at 512-343-2758.';
    errorDiv.style.display = 'block';
    errorDiv.focus();
    btn.disabled = false;
    btn.innerText = 'Request Appointment';
    if (window.turnstile && typeof window.turnstile.reset === 'function') {
      window.turnstile.reset();
    }
  }
});
</script>
</body>
</html>
