<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.marianwthompson.com;https://marianwthompson.com';

// 2. Robust regex split: handles BOTH commas and semicolons gracefully
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

// 3. Clean and join them up with spaces for the CSP string
$cspOrigins = implode(' ', array_filter(array_unique($allowed_origins)));

// 4. Send the perfect, browser-approved header
header("Content-Security-Policy: frame-ancestors 'self' " . $cspOrigins . ";");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Contact Form</title>
<link rel="stylesheet" href="fonts/fonts.css">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: "Frank Ruhl Libre", Georgia, serif;
      margin: 0;
      padding: 12px;
      color: #222;
      background: #fff;
    }
    .form-container {
      max-width: 600px;
      margin: 0;
    }

    /* 2-Column Row on Desktop, Single Column on Mobile (WCAG 1.4.10 Reflow) */
    .form-row {
      display: flex;
      gap: 15px;
      margin-bottom: 15px;
    }
    .form-col {
      flex: 1 1 0;
      min-width: 0;
    }
    .field-container {
      margin: 0 0 15px 0;
    }
    @media (max-width: 480px) {
      .form-row {
        flex-direction: column;
        gap: 15px;
      }
      input[type="text"], input[type="email"], input[type="tel"], input[type="url"], select, textarea {
        font-size: 16px;
      }
    }

    label {
      display: block;
      font-size: 1rem;
      font-weight: 500;
      margin: 0 0 5px 0;
      width: auto;
      color: #111;
    }
    .required {
      color: #b71c1c;
      font-weight: bold;
    }

    input[type="text"], input[type="email"], input[type="tel"], input[type="url"], select, textarea {
      font-family: "Frank Ruhl Libre", Georgia, serif;
      font-size: 1rem;
      font-weight: 500;
      width: 100%;
      padding: 10px;
      border: 1px solid #767676; /* Meets WCAG 1.4.11 3:1 UI border contrast */
      border-radius: 2px;
      color: #111;
      background-color: #fff;
    }
    ::placeholder {
      color: #595959;
      opacity: 1;
    }
    textarea {
      resize: vertical;
    }

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
      font-size: 0.9rem;
      font-weight: 500;
      margin-top: 4px;
    }
    .ap-field-error:empty {
      display: none;
    }
    .ap-error-summary {
      border-left: 4px solid #b71c1c;
      background-color: #fff5f5;
      color: #7f1d1d;
      padding: 12px 16px;
      margin-bottom: 16px;
      border-radius: 4px;
      font-size: 0.95rem;
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
      outline: 3px solid #417fa6;
      outline-offset: 2px;
    }

    /* Consent Checkbox */
    .checkbox-container {
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      margin-top: 20px;
    }
    .checkbox-container input[type="checkbox"] {
      width: 18px;
      height: 18px;
      margin-right: 12px;
      margin-top: 3px;
      flex-shrink: 0;
      accent-color: #417fa6;
      cursor: pointer;
    }
    .checkbox-container label {
      flex: 1 1 calc(100% - 30px);
      display: inline;
      font-weight: 400;
      font-size: 0.95rem;
      line-height: 1.4;
      cursor: pointer;
    }
    .checkbox-container .ap-field-error {
      flex-basis: 100%;
      margin-left: 30px;
    }

    button, input[type=button], input[type=reset], input[type=submit] {
      background: #417fa6;
      fill: #417fa6;
      color: #ffffff;
      border-color: #417fa6;
      font-family: "Frank Ruhl Libre", Georgia, serif;
      font-size: 1.1em;
      font-weight: 700;
      line-height: 1em;
      border-style: solid;
      border-width: 2px;
      border-radius: 40px;
      padding: 10px 25px;
      margin-top: 15px;
      cursor: pointer;
      transition: background 0.2s ease, color 0.2s ease;
    }
    button:hover {
      background: #ffffff;
      color: #417fa6;
    }
    button:disabled {
      opacity: 0.7;
      cursor: not-allowed;
    }

    .honeypot {
      display: none !important;
    }

    #success-message {
      display: none;
      background-color: #e8f5e9;
      color: #1b5e20;
      border: 1px solid #a5d6a7;
      padding: 25px;
      border-radius: 4px;
      text-align: center;
      max-width: 600px;
      margin: 0;
    }

    .attribution {
      color: #0a0a0a;
      font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, "Helvetica Neue", Arial, sans-serif;
      font-size: 13px;
      line-height: 2em;
      font-weight: 400;
      -webkit-font-smoothing: antialiased;
      font-style: normal;
      text-transform: uppercase;
      margin-top: 14px;
    }
    .attribution a:link, .attribution a:hover, .attribution a:visited {
      color: #554F9B;
      text-decoration: none;
    }
    .attribution a:hover, .attribution a:focus-visible {
      text-decoration: underline;
    }
      .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
  </style>
</head>

<body>
<main class="form-container">
  <!-- ACCESSIBLE SUCCESS MESSAGE -->
  <div id="success-message" role="status" aria-live="polite" tabindex="-1">
    <h2 style="margin-top: 0; font-size: 1.35rem;">Message Sent Securely</h2>
    <p style="margin-bottom: 0;">Thank you! Your secure message has been received. We will get back to you shortly.</p>
  </div>

  <form id="contact-form" novalidate aria-label="Secure Contact Form">
    <!-- Honeypot -->
    <div class="honeypot" aria-hidden="true">
      <label for="fax_number">Leave this field blank</label>
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

    <!-- Row 2: Email -->
    <div class="field-container">
      <label for="email">Email Address <span class="required" aria-hidden="true">*</span></label>
      <input type="email" id="email" name="email" autocomplete="email" required aria-required="true">
    </div>

    <!-- Row 3: Phone -->
    <div class="field-container">
      <label for="phone">Phone Number <span class="required" aria-hidden="true">*</span></label>
      <input type="tel" id="phone" name="phone" autocomplete="tel" required aria-required="true">
    </div>

    <!-- Row 4: How You Found Me & Referral/Other -->
    <div class="form-row">
      <div class="form-col">
        <label for="how_you_find">How you found me <span class="required" aria-hidden="true">*</span></label>
        <select id="how_you_find" name="how_you_find" required aria-required="true">
          <option value="" disabled selected hidden>Select...</option>
          <option value="Google">Google/Search</option>
          <option value="AI">AI/ChatGPT/Gemini</option>
          <option value="Referral">Referral (Please specify below)</option>
          <option value="Other">Other (Please specify below)</option>
        </select>
      </div>
      <div class="form-col">
        <label for="referal_name" id="referal_name_label">Referral/Other:</label>
        <input type="text" id="referal_name" name="referal_name">
      </div>
    </div>

    <!-- Row 5: Message -->
    <div class="field-container">
      <label for="message">Your Message <span class="required" aria-hidden="true">*</span></label>
      <textarea id="message" name="message" rows="5" required aria-required="true"></textarea>
    </div>

    <!-- Row 6: PHI Consent Checkbox -->
    <div class="field-container checkbox-container">
      <input name="consent" type="checkbox" required aria-required="true" id="consent" value="yes">
      <label for="consent">
        By checking this box and submitting this form, I consent to the collection and processing of the information provided, which may include Protected Health Information (PHI). I authorize this practice to contact me via email, phone, text message, or voicemail. I acknowledge and understand that standard email and text messaging are not secure or encrypted methods of communication. I accept the risks of communicating via unencrypted email and text message (including the risk of unauthorized access or interception by third parties) and explicitly request and consent to receive email and text communications from this practice regarding my inquiry or care. <span class="required" aria-hidden="true">*</span>
      </label>
    </div>

    <div class="cf-turnstile" data-sitekey="0x4AAAAAABewuznfN6LBlp7v" data-theme="light"></div>

    <button type="submit" id="submit-btn">Send Message</button>

    <p class="attribution">
      <a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign=mwt" target="_blank" rel="noopener">HIPAA Compliant Contact Form<span class=\"sr-only\"> (opens in a new tab)</span></a>
    </p>
  </form>
</main>

<script>
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('contact-form');
  if (!form) return;

  // Automatic iframe height reporting via ResizeObserver
  function sendHeightToParent() {
    if (!window.parent || window.parent === window) return;
    const container = document.querySelector('.form-container') || document.body;
    const exactHeight = Math.ceil(container.getBoundingClientRect().height) + 28;
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

  // Toggle conditional requirement when "Referral" or "Other" is selected
  const howSelect = document.getElementById('how_you_find');
  const referalInput = document.getElementById('referal_name');
  const referalLabel = document.getElementById('referal_name_label');

  if (howSelect && referalInput) {
    howSelect.addEventListener('change', function () {
      const needsSpec = howSelect.value === 'Referral' || howSelect.value === 'Other';
      if (needsSpec) {
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
      if (explicitLabel) return explicitLabel.textContent.replace(/[*:]/g, '').trim();
    }
    const parentLabel = input.closest('label');
    if (parentLabel) return parentLabel.textContent.replace(/[*:] /g, '').trim();
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
        const container = input.closest('.checkbox-container');
        if (container) {
          container.appendChild(errSpan);
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
      return 'You must accept the communication consent agreement before submitting.';
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

    const submitBtn = document.getElementById('submit-btn');
    const originalBtnText = submitBtn ? submitBtn.innerText : 'Send Message';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerText = 'Securing connection...';
    }

    try {
      const getValue = (id) => {
        const el = document.getElementById(id);
        return el ? el.value.trim() : '';
      };

      const consentCheckbox = document.getElementById('consent');

      const formData = {
        first_name: getValue('first_name'),
        last_name: getValue('last_name'),
        email: getValue('email'),
        phone: getValue('phone'),
        how_you_find: getValue('how_you_find'),
        referal_name: getValue('referal_name'),
        message: getValue('message'),
        consent: (consentCheckbox && consentCheckbox.checked) ? 'yes' : 'no',
        fax_number: getValue('fax_number')
      };

      const turnstileInput = document.querySelector('[name="cf-turnstile-response"]');
      if (turnstileInput && turnstileInput.value) {
        formData['cf-turnstile-response'] = turnstileInput.value;
      }

      const response = await fetch('/submit-form.php', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(formData)
      });

      const result = await response.json();

      if (response.ok && result.status === 'success') {
        form.style.display = 'none';

        const successMessage = document.getElementById('success-message');
        if (successMessage) {
          successMessage.style.display = 'block';
          sendHeightToParent();
          window.scrollTo({ top: 0, behavior: 'smooth' });
          successMessage.focus();
        }

        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
        }

        form.reset();
      } else {
        showServerError(
          form,
          result.message || 'A security or validation error occurred.',
          result.field_errors
        );
        if (typeof turnstile !== 'undefined') turnstile.reset();
      }
    } catch (err) {
      console.error('Argon Pipeline JS Catch:', err);
      showServerError(form, 'An internal system error prevented this message from sending. Please try again.');
      if (typeof turnstile !== 'undefined') turnstile.reset();
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerText = originalBtnText;
      }
    }
  });
});
</script>

</body>
</html>