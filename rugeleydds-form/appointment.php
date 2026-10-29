<?php require_once 'config.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Make an Appointment - John K Rugeley, DDS</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 16px; color: #333; background: #fff; }
    .form-container { max-width: 600px; margin: 0 auto; }
    .form-group { margin-bottom: 16px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; }
    .required { color: #d32f2f; }
    input[type="text"], input[type="email"], input[type="tel"], select, textarea {
      width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 15px;
    }
    textarea { height: 100px; resize: vertical; }
    .radio-group { display: flex; gap: 20px; margin-top: 6px; }
    .radio-group label { font-weight: normal; display: inline-flex; align-items: center; gap: 6px; }
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
    <h3>Appointment Request Received</h3>
    <p>Thank you! Our scheduling coordinator will review your requested dates and contact you to confirm your visit.</p>
  </div>

  <form id="appointment-form" action="submit.php" method="POST">
    <input type="hidden" name="form_type" value="appointment">

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
      <label>Patient Type <span class="required">*</span></label>
      <div class="radio-group">
        <label><input type="radio" name="patient_type" value="Current Patient" required> Current Patient</label>
        <label><input type="radio" name="patient_type" value="New Patient" required> New Patient</label>
      </div>
    </div>

    <div class="form-group">
      <label for="preferred_dates">Preferred Dates <span class="required">*</span></label>
      <input type="text" id="preferred_dates" name="preferred_dates" placeholder="e.g. Next Tuesday or Thursday" required>
    </div>

    <div class="form-group">
      <label for="preferred_times">Preferred Times <span class="required">*</span></label>
      <input type="text" id="preferred_times" name="preferred_times" placeholder="e.g. Morning (8am - 12pm) or After 2pm" required>
    </div>

    <div class="form-group">
      <label for="reason">Please describe your reason for visiting Dr. Rugeley <span class="required">*</span></label>
      <textarea id="reason" name="reason" placeholder="e.g. Routine cleaning and checkup, tooth pain, consultation" required></textarea>
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

    <button type="submit" id="submit-btn" class="btn-submit">Request Appointment</button>
  </form>
</div>

<script>
document.getElementById('appointment-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const errorDiv = document.getElementById('error-message');
  const successDiv = document.getElementById('success-message');

  errorDiv.style.display = 'none';
  btn.disabled = true;
  btn.innerText = 'Submitting Request...';

  try {
    const formData = new FormData(this);
    const res = await fetch('submit.php', { method: 'POST', body: formData });
    const data = await res.json();

    if (data.success) {
      document.getElementById('appointment-form').style.display = 'none';
      successDiv.style.display = 'block';
      window.scrollTo({ top: 0, behavior: 'smooth' });
      successDiv.focus();
      window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
    } else {
      errorDiv.innerText = data.error || 'An error occurred while submitting. Please call our office at 512-343-2758.';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btn.innerText = 'Request Appointment';
    }
  } catch (err) {
    errorDiv.innerText = 'Unable to send appointment request. Please call our office at 512-343-2758.';
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btn.innerText = 'Request Appointment';
  }
});
</script>
</body>
</html>
