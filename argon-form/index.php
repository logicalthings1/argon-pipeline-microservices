<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.argonpipeline.com;https://argonpipeline.com';

// 2. Robust regex split: handles BOTH commas and semicolons gracefully
$allowed_origins = preg_split('/[;,]\s*/', trim($allowed_env));

// 3. Clean and join them up with spaces for the CSP string
$cspOrigins = implode(' ', array_filter(array_unique($allowed_origins)));

// 4. Send browser security headers
header("Content-Security-Policy: frame-ancestors 'self' " . $cspOrigins . ";");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Argon Pipeline Contact Form</title>
<link rel="stylesheet" href="fonts/fonts.css">
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

    /* 2-Column Row on Desktop, Single Column on Mobile (WCAG 1.4.10 Reflow) */
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
    @media (max-width: 480px) {
      .form-row {
        flex-direction: column;
      }
    }

    label {
      display: block;
      font-size: 0.95rem;
      font-weight: 500;
      margin-bottom: 5px;
      color: #111;
    }
    .required {
      color: #b71c1c;
      font-weight: bold;
    }

    input[type="text"], input[type="email"], input[type="url"], input[type="tel"], select, textarea {
      font-family: Figtree, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 1rem;
      font-weight: 500;
      width: 100%;
      padding: 9px 11px;
      border: 1px solid #767676; /* Meets WCAG 1.4.11 3:1 UI border contrast */
      border-radius: 4px;
      color: #111;
      background-color: #fff;
    }
    ::placeholder {
      color: #595959;
      opacity: 1;
    }
    textarea {
      height: 95px;
      resize: vertical;
    }

    /* WCAG 2.1 AA Invalid Field & Error States */
    [aria-invalid="true"] {
      border: 2px solid #b71c1c !important;
      background-color: #fffafa !important;
    }
    .ap-field-error {
      display: block;
      color: #b71c1c;
      font-size: 0.875rem;
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
      font-weight: 600;
      text-decoration: underline;
    }

    /* WCAG Focus Indicators */
    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible,
    .ap-error-summary:focus-visible, .ap-error-summary a:focus-visible, #turnstile-container:focus-visible {
      outline: 3px solid #554F9B;
      outline-offset: 2px;
    }

    /* Pill Submit Button */
    .btn-submit {
      border-radius: 30px;
      background: #554F9B;
      color: #ffffff;
      padding: 0.5em 1.4em;
      border: 0;
      font-size: 1.15rem;
      font-weight: 500;
      line-height: 1.6;
      display: inline-block;
      font-family: Figtree, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      cursor: pointer;
      transition: background 0.2s ease;
      margin-top: 8px;
    }
    .btn-submit:hover {
      background: #433d82;
    }
    .btn-submit:disabled {
      background: #6e69a8;
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
      padding: 20px;
      border-radius: 4px;
      text-align: left;
      max-width: 600px;
      margin: 0;
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
  <div id="success-message" role="status" aria-live="polite" tabindex="-1">
    <h2 style="margin-top: 0; font-size: 1.25rem;">Message Sent Securely</h2>
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
        <input type="text" id="url" name="url" autocomplete="url" required aria-required="true">
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
        <label for="specify_other" id="specify_other_label">Specify Other</label>
        <input type="text" id="specify_other" name="specify_other" placeholder="If other, please specify">
      </div>
    </div>

    <!-- Row 4: Message (Full Width) -->
    <div class="form-full">
      <label for="message">Question or Comment <span class="required" aria-hidden="true">*</span></label>
      <textarea id="message" name="message" required aria-required="true"></textarea>
    </div>
    
    <!-- Turnstile (Light Theme) -->
    <div class="form-full" id="turnstile-container" role="group" aria-label="Spam protection verification" tabindex="-1">
      <div class="cf-turnstile" data-sitekey="0x4AAAAAAETIrCfMZKCInxXw" data-theme="light"></div>
    </div>

    <button type="submit" id="submit-btn" class="btn-submit">Send Message</button>
  </form>
</main>

<script>
(function () {
  const form = document.getElementById('argon-secure-form');

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

  // Toggle conditional requirement when "Other" is selected
  const serviceSelect = document.getElementById('service');
  const specifyOtherInput = document.getElementById('specify_other');
  const specifyOtherLabel = document.getElementById('specify_other_label');

  if (serviceSelect && specifyOtherInput) {
    serviceSelect.addEventListener('change', function () {
      const isOther = serviceSelect.value === 'other';
      if (isOther) {
        specifyOtherInput.setAttribute('required', '');
        specifyOtherInput.setAttribute('aria-required', 'true');
        if (specifyOtherLabel && !specifyOtherLabel.querySelector('.required')) {
          specifyOtherLabel.insertAdjacentHTML('beforeend', ' <span class="required" aria-hidden="true">*</span>');
        }
      } else {
        specifyOtherInput.removeAttribute('required');
        specifyOtherInput.removeAttribute('aria-required');
        specifyOtherInput.removeAttribute('aria-invalid');
        const errSpan = document.getElementById('specify_other-error');
        if (errSpan) errSpan.textContent = '';
        const reqMark = specifyOtherLabel ? specifyOtherLabel.querySelector('.required') : null;
        if (reqMark) reqMark.remove();
      }
      sendHeightToParent();
    });
  }

  // Dynamic, field-agnostic WCAG 2.1 AA validation helpers
  function getFieldLabel(targetForm, input) {
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
      input.insertAdjacentElement('afterend', errSpan);
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
      return `${label} must be checked to proceed.`;
    }
    if (isRequired && val.length === 0) {
      return `${label} is required.`;
    }
    if (val.length > 0 && input.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
      return `Enter a valid email address for ${label} (for example, name@practice.com).`;
    }
    if (val.length > 0 && (input.type === 'url' || input.name === 'url')) {
      try {
        const parsed = new URL(val.startsWith('http') ? val : `https://${val}`);
        if (!parsed.hostname.includes('.')) throw new Error('Invalid host');
      } catch {
        return `Enter a valid website URL for ${label} (for example, https://example.com).`;
      }
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
    } else if (/security check|turnstile|bot challenge/i.test(message)) {
      extraLinks.push('<li><a href="#turnstile-container">Security Verification:</a> Complete the verification widget below.</li>');
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
          sendHeightToParent();
          window.scrollTo({ top: 0, behavior: 'smooth' });
          successDiv.focus();
        }

        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
        }

        form.reset();
      } else {
        showServerError(
          form,
          res.message || 'Your submission failed. Please contact info@argonpipeline.com.',
          res.field_errors
        );
        console.error('Server Debug Info:', res);
        if (typeof turnstile !== 'undefined') turnstile.reset();
      }

    } catch (error) {
      showServerError(form, 'A secure connection error occurred. Please check your connection and try again.');
      console.error('Frontend Error Tracking:', error);
      if (typeof turnstile !== 'undefined') turnstile.reset();
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = originalBtnText;
      }
    }
  });
})();
</script>

</body>
</html>