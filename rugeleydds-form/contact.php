<?php
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.rugeleydds.com;https://rugeleydds.com';
$allowed_origins = array_filter(array_unique(preg_split('/[;,]\s*/', trim($allowed_env))));
$cspOrigins = implode(' ', $allowed_origins);

header("Content-Security-Policy: frame-ancestors 'self'" . ($cspOrigins !== '' ? " {$cspOrigins}" : '') . ";");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contact Us - John K Rugeley, DDS</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body { font-family: Quicksand, sans-serif; margin: 0; padding: 0; color: #222; background: #fff; }
    .form-container { max-width: 600px; margin: 0; }

    /* 2-Column Row on Desktop, Single Column on Mobile (WCAG 1.4.10 Reflow) */
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
    @media (max-width: 480px) {
      .form-row {
        flex-direction: column;
      }
      input[type="text"], input[type="email"], input[type="tel"], input[type="url"], select, textarea {
        font-size: 16px;
      }
    }

    label, legend { display: block; font-family: Quicksand, sans-serif; font-weight: 600; margin-bottom: 4px; font-size: 14px; color: #111; }
    .required { color: #b71c1c; font-weight: bold; }

    input[type="text"], input[type="email"], input[type="tel"], input[type="url"], select, textarea {
      width: 100%; padding: 8px 10px; border: 1px solid #767676; border-radius: 4px; font-size: 14px; color: #111; background-color: #fff; font-family: inherit;
    }
    ::placeholder {
      color: #595959;
      opacity: 1;
    }
    textarea { height: 75px; resize: vertical; }

    /* WCAG 2.1 AA Invalid Field & Error States */
    [aria-invalid="true"] {
      border: 2px solid #b71c1c !important;
      background-color: #fffafa !important;
    }
    input[type="checkbox"][aria-invalid="true"] {
      outline: 2px solid #b71c1c;
      outline-offset: 2px;
    }
    .ap-field-error {
      display: block;
      color: #b71c1c;
      font-size: 13px;
      font-weight: 600;
      margin-top: 4px;
    }
    .ap-field-error:empty {
      display: none;
    }
    .ap-error-summary {
      border-left: 4px solid #b71c1c;
      background-color: #fff5f5;
      color: #7f1d1d;
      padding: 12px 14px;
      margin-bottom: 14px;
      border-radius: 4px;
      font-size: 14px;
      line-height: 1.4;
    }
    .ap-error-summary ul {
      margin: 6px 0 0 0;
      padding-left: 20px;
    }
    .ap-error-summary li {
      margin-bottom: 4px;
    }
    .ap-error-summary a {
      color: #7f1d1d;
      font-weight: 700;
      text-decoration: underline;
    }

    /* WCAG Focus Indicators */
    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible, .ap-error-summary:focus-visible, .ap-error-summary a:focus-visible {
      outline: 3px solid #1a568c;
      outline-offset: 2px;
    }

    /* Consent Checkbox */
    .consent-group { display: flex; flex-wrap: wrap; align-items: flex-start; gap: 8px; margin: 10px 0 14px 0; font-size: 13px; line-height: 1.4; color: #222; }
    .consent-group input[type="checkbox"] { width: 18px; height: 18px; margin-top: 1px; flex-shrink: 0; accent-color: #1a568c; cursor: pointer; }
    .consent-group label { flex: 1 1 calc(100% - 26px); font-size: 13px; font-weight: normal; cursor: pointer; margin: 0; }
    .consent-group .ap-field-error { flex-basis: 100%; margin-left: 26px; }

    /* Submit Button */
    .btn-submit {
      background-color: #2C7F8C;
      font-family: Quicksand, sans-serif;
      font-weight: 500;
      font-size: 18px;
      color: #ffffff;
      border-style: solid;
      border-width: 0px;
      border-color: rgba(255, 255, 255, 0);
      border-radius: 4px;
      padding: 10px 15px;
      cursor: pointer;
    }
    .btn-submit:hover { background-color: #000000; }
    .btn-submit:disabled { background-color: #728496; cursor: not-allowed; }

    .honeypot { display: none !important; }

    /* Success Alert */
    #success-message { display: none; background: #e8f5e9; border: 2px solid #2e7d32; color: #1b5e20; padding: 16px; border-radius: 4px; text-align: left; }

    /* Attribution */
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
      color: #4a4a4a;
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
  <div id="success-message" role="status" aria-live="polite" tabindex="-1">
    <h2 style="margin-top: 0; font-size: 1.25rem;">Thank you!</h2>
    <p style="margin-bottom: 0;">Your message has been securely sent to our front desk team. We will be in touch shortly.</p>
  </div>

  <form id="contact-form" action="submit-form.php" method="POST" novalidate aria-label="Contact Us Form">
    <input type="hidden" name="form_type" value="contact">

    <!-- Honeypot -->
    <div class="honeypot" aria-hidden="true">
      <input type="text" name="fax_number" tabindex="-1" autocomplete="off">
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

    <!-- Row 2: Email & Phone -->
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

    <!-- Row 3: How Did You Find Us & Referral Details -->
    <div class="form-row">
      <div class="form-col">
        <label for="how_you_find">How did you find us? <span class="required" aria-hidden="true">*</span></label>
        <select id="how_you_find" name="how_you_find" required aria-required="true">
          <option value="" disabled selected hidden>Please select</option>
          <option value="Google">Google / Search</option>
          <option value="AI/ChatGPT/Gemini">AI / ChatGPT / Gemini</option>
          <option value="Insurance">Insurance Provider</option>
          <option value="Friend/Family">Friend / Family</option>
          <option value="Other">Referral / Other</option>
        </select>
      </div>
      <div class="form-col">
        <label for="referal_name" id="referal_name_label">Referral / Other Details</label>
        <input type="text" id="referal_name" name="referal_name" placeholder="Name or source">
      </div>
    </div>

    <!-- Row 4: Message (Full Width) -->
    <div class="form-full">
      <label for="message">Message <span class="required" aria-hidden="true">*</span></label>
      <textarea id="message" name="message" required aria-required="true"></textarea>
    </div>

    <!-- Row 5: PHI Consent Checkbox -->
    <div class="consent-group">
      <input type="checkbox" id="consent" name="consent" value="yes" required aria-required="true">
      <label for="consent">
        By checking this box and submitting this form, I consent to the collection and processing of the information provided, which may include Protected Health Information (PHI). I authorize this practice to contact me via email, phone, text message, or voicemail. I acknowledge and understand that standard email and text messaging are not secure or encrypted methods of communication. I accept the risks of communicating via unencrypted email and text message (including the risk of unauthorized access or interception by third parties) and explicitly request and consent to receive email and text communications from this practice regarding my inquiry or <span style="white-space: nowrap;">care. <span class="required" aria-hidden="true">*</span></span>
      </label>
    </div>

    <!-- Cloudflare Turnstile (Light Theme) -->
    <div class="form-full" id="turnstile-container" tabindex="-1">
      <div class="cf-turnstile" data-theme="light" data-sitekey="<?= htmlspecialchars(getenv('TURNSTILE_SITE_KEY') ?: '', ENT_QUOTES, 'UTF-8') ?>"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Send Message</button>

    <p class="attribution">
      <a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign=rugeleydds" target="_blank" rel="noopener">HIPAA Compliant Contact Form</a>
    </p>
  </form>
</main>

<script>
(function () {
  const form = document.getElementById('contact-form');
  const btn = document.getElementById('submit-btn');
  const successDiv = document.getElementById('success-message');

  // Automatic iframe height reporting via ResizeObserver
  function sendHeightToParent() {
    if (!window.parent || window.parent === window) return;
    const container = document.querySelector('.form-container') || document.body;
    const exactHeight = Math.ceil(container.getBoundingClientRect().height) + 12;
    window.parent.postMessage({
      action: 'argonResize',
      height: exactHeight
    }, '*');
  }

  if ('ResizeObserver' in window) {
    const ro = new ResizeObserver(() => sendHeightToParent());
    ro.observe(document.body);
    const container = document.querySelector('.form-container');
    if (container) ro.observe(container);
  }
  window.addEventListener('load', sendHeightToParent);

  // Toggle conditional requirement when "Referral / Other" is selected
  const howSelect = document.getElementById('how_you_find');
  const referalInput = document.getElementById('referal_name');
  const referalLabel = document.getElementById('referal_name_label');

  if (howSelect && referalInput) {
    howSelect.addEventListener('change', function () {
      const isOther = howSelect.value === 'Other';
      if (isOther) {
        referalInput.setAttribute('required', '');
        referalInput.setAttribute('aria-required', 'true');
        if (referalLabel && !referalLabel.querySelector('.required')) {
          referalLabel.insertAdjacentHTML('beforeend', ' <span class="required" aria-hidden="true">*</span>');
        }
      } else {
        referalInput.removeAttribute('required');
        referalInput.removeAttribute('aria-required');
        referalInput.removeAttribute('aria-invalid');
        const errSpan = document.getElementById('referal_name-error');
        if (errSpan) errSpan.textContent = '';
        const reqMark = referalLabel ? referalLabel.querySelector('.required') : null;
        if (reqMark) reqMark.remove();
      }
      sendHeightToParent();
    });
  }

  // Dynamic, field-agnostic WCAG 2.1 AA validation helpers
  function getFieldLabel(targetForm, input) {
    if (input.type === 'checkbox' && input.id === 'consent') {
      return 'HIPAA & Electronic Communication Consent';
    }
    if (input.id) {
      const explicitLabel = targetForm.querySelector(`label[for="${CSS.escape(input.id)}"]`);
      if (explicitLabel) return explicitLabel.textContent.replace(/\*/g, '').trim();
    }
    const parentLabel = input.closest('label');
    if (parentLabel) return parentLabel.textContent.replace(/\*/g, '').trim();
    return input.getAttribute('aria-label') || input.name || 'This field';
  }

  function ensureErrorSummary(targetForm) {
    let summary = targetForm.querySelector('.ap-error-summary');
    if (!summary) {
      summary = document.createElement('div');
      summary.className = 'ap-error-summary';
      summary.setAttribute('role', 'alert');
      summary.setAttribute('aria-live', 'assertive');
      summary.setAttribute('tabindex', '-1');
      summary.hidden = true;
      targetForm.prepend(summary);
    }
    return summary;
  }

  function ensureFieldErrorSpan(input) {
    if (!input.id) {
      input.id = 'ap-field-' + Math.random().toString(36).slice(2, 9);
    }
    const errId = `${input.id}-error`;
    let errSpan = document.getElementById(errId);
    if (!errSpan) {
      errSpan = document.createElement('span');
      errSpan.id = errId;
      errSpan.className = 'ap-field-error';
      if (input.type === 'checkbox') {
        const group = input.closest('.consent-group');
        if (group) {
          group.appendChild(errSpan);
        } else {
          input.insertAdjacentElement('afterend', errSpan);
        }
      } else {
        input.insertAdjacentElement('afterend', errSpan);
      }
    }
    const describedBy = (input.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
    if (!describedBy.includes(errId)) {
      describedBy.push(errId);
      input.setAttribute('aria-describedby', describedBy.join(' '));
    }
    return errSpan;
  }

  function isVisible(el) {
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }

  function validateSingleField(targetForm, input) {
    if (!isVisible(input) || input.disabled) return null;

    const label = getFieldLabel(targetForm, input);
    const val = (input.value || '').trim();
    const isRequired = input.hasAttribute('required') || input.getAttribute('aria-required') === 'true';

    if (input.type === 'checkbox' && isRequired && !input.checked) {
      return 'You must check the consent box to submit your message.';
    }
    if (isRequired && val.length === 0) {
      return `${label} is required.`;
    }
    if (val.length > 0 && input.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
      return `Enter a valid email address for ${label} (for example, name@domain.com).`;
    }
    if (val.length > 0 && input.type === 'tel' && val.replace(/\D/g, '').length < 10) {
      return `Enter a valid 10-digit phone number for ${label}.`;
    }
    return null;
  }

  function validateForm(targetForm) {
    const summary = ensureErrorSummary(targetForm);
    const fields = Array.from(targetForm.querySelectorAll('input, select, textarea'))
      .filter(el => el.type !== 'hidden' && el.type !== 'submit' && el.type !== 'button' && !el.closest('.honeypot'));

    const errors = [];

    fields.forEach(input => {
      const errSpan = ensureFieldErrorSpan(input);
      const message = validateSingleField(targetForm, input);

      if (message) {
        input.setAttribute('aria-invalid', 'true');
        errSpan.textContent = message;
        errors.push({ input, label: getFieldLabel(targetForm, input), message });
      } else {
        input.removeAttribute('aria-invalid');
        errSpan.textContent = '';
      }
    });

    if (errors.length > 0) {
      summary.innerHTML =
        `<strong>Please fix ${errors.length} ${errors.length === 1 ? 'error' : 'errors'} before submitting:</strong>` +
        `<ul>` +
        errors.map(e => `<li><a href="#${e.input.id}">${e.label}:</a> ${e.message}</li>`).join('') +
        `</ul>`;
      summary.hidden = false;
      sendHeightToParent();
      errors[0].input.focus();
      return false;
    }

    summary.hidden = true;
    summary.innerHTML = '';
    sendHeightToParent();
    return true;
  }

  function showServerError(targetForm, message, fieldErrors) {
    const summary = ensureErrorSummary(targetForm);
    const extraLinks = [];

    if (fieldErrors && typeof fieldErrors === 'object') {
      Object.entries(fieldErrors).forEach(([fieldName, msg]) => {
        const input = targetForm.querySelector(`[name="${CSS.escape(fieldName)}"]`);
        if (input) {
          const errSpan = ensureFieldErrorSpan(input);
          input.setAttribute('aria-invalid', 'true');
          errSpan.textContent = msg;
          extraLinks.push(`<li><a href="#${input.id}">${getFieldLabel(targetForm, input)}:</a> ${msg}</li>`);
        }
      });
    }

    summary.innerHTML = `<strong>Unable to send message:</strong> ${message}` +
      (extraLinks.length ? `<ul>${extraLinks.join('')}</ul>` : '');
    summary.hidden = false;
    sendHeightToParent();
    summary.focus();
  }

  // Clear field-level error immediately as the user corrects their input
  ['input', 'change'].forEach(evt => {
    form.addEventListener(evt, function (e) {
      const input = e.target;
      if (input && input.getAttribute('aria-invalid') === 'true') {
        const msg = validateSingleField(form, input);
        if (!msg) {
          input.removeAttribute('aria-invalid');
          const errSpan = document.getElementById(`${input.id}-error`);
          if (errSpan) errSpan.textContent = '';
          sendHeightToParent();
        }
      }
    });
  });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    if (!validateForm(form)) {
      return;
    }

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

      if (res.ok && (data.status === 'success' || data.success === true)) {
        form.style.display = 'none';
        successDiv.style.display = 'block';
        sendHeightToParent();
        successDiv.focus();
        window.scrollTo({ top: 0, behavior: 'smooth' });
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
        }
      } else {
        showServerError(
          form,
          data.message || data.error || 'An error occurred while submitting. Please call our office at 512-343-2758.',
          data.field_errors
        );
        btn.disabled = false;
        btn.innerText = 'Send Message';
        if (window.turnstile && typeof window.turnstile.reset === 'function') {
          window.turnstile.reset();
        }
      }
    } catch (err) {
      showServerError(form, 'Unable to send message right now. Please call our office at 512-343-2758.');
      btn.disabled = false;
      btn.innerText = 'Send Message';
      if (window.turnstile && typeof window.turnstile.reset === 'function') {
        window.turnstile.reset();
      }
    }
  });
})();
</script>
</body>
</html>