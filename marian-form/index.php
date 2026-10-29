<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.marianwthompson.com;https://marianwthompson.com';

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
  <title>Secure Contact Form</title>
	<style>
		form, div {font-family: "Frank Ruhl Libre", sans-serif}
		.field-container {margin: 0 0 15px 0;}
		label {
			display: block;
			font-size: 1rem;
			font-weight: 500;
			margin: 0 0 5px 0;
			width: auto;
		}
		input, select, textarea {font-size:1rem; font-weight:500; width:100%; padding:10px; box-sizing:border-box; border:solid #bbbbbb 1px; border-radius: 2px;}
		.left-field {
			width:48%;
			float: left;
			margin-right: 15px;
		}
		.right-field {
			width:48%;
			float: left;
		}
		.clear {clear: both;}
		.checkbox-container {
			display: flex;
			align-items: flex-start;
			margin-top: 20px;
		}
		.checkbox-container input[type="checkbox"] {
			width: auto;
			margin-right: 12px;
			margin-top: 4px;
			transform: scale(1.2);
		}
		.checkbox-container label {
			display: inline;
			font-weight: 400;
			font-size: 0.95rem;
			line-height: 1.4;
		}
		button, input[type=button], input[type=reset], input[type=submit] {
			background: #417fa6;
			fill: #417fa6;
			color: #ffffff;
			border-color: #417fa6;
			font-family: "Frank Ruhl Libre", serif;
			font-size: 1.1em;
			font-weight: 700;
			line-height: 1em;
			border-style: solid;
			border-width: 2px;
			border-radius: 40px;
			padding: 10px 25px;
			margin-top: 15px;
			cursor: pointer;
		}
		button:hover {background: #ffffff; color: #417fa6;}
		.required {color: red; font-weight: bold;}
		.attribution {
			color: #0a0a0a;
			font-family: -apple-system, system-ui, blinkmacsystemfont, "Segoe UI", roboto, oxygen, ubuntu, "Helvetica Neue", arial, sans-serif;
			font-size: 13px;
			line-height:2em;
			font-weight: 400;
			-webkit-font-smoothing: antialiased;
			font-style: normal;
			text-transform: uppercase;
		}
		.attribution a:link, a:hover, a:visited {
			color: #554F9B;
		}
		@media (max-width: 480px) {
			.left-field {
				width: 48%;
			}
			.right-field {
				width:47%;
			}
		}
	</style>
	<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>

<body>

<!-- ACCESSIBLE SUCCESS MESSAGE -->
<div id="success-message" role="status" aria-live="polite" tabindex="-1" style="display: none; background-color: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; padding: 25px; border-radius: 4px; text-align: center; max-width: 600px; margin: 0 auto;">
    <h3 style="margin-top: 0;">Message Sent Securely</h3>
    <p style="margin-bottom: 0;">Thank you! Your secure message has been received. We will get back to you shortly.</p>
</div>
	
<form id="contact-form" style="max-width: 600px; margin: 0; padding:0;">

<!-- "fax number" -->
<div style="position: absolute; left: -5000px;" aria-hidden="true">
  <label for="fax_number">Leave this field blank</label>
  <input type="text" id="fax_number" name="fax_number" tabindex="-1" autocomplete="off">
</div>
	
  <div class="field-container left-field">
    <label for="first_name">First Name <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="first_name" name="first_name" autocomplete="given-name" required>
  </div>

  <div class="field-container right-field">
    <label for="last_name">Last Name <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="last_name" name="last_name" autocomplete="family-name" required>
  </div>

  <div class="field-container clear">
    <label for="email">Email Address <span class="required" aria-hidden="true">*</span></label>
    <input type="email" id="email" name="email" autocomplete="email" required>
  </div>

  <div class="field-container">
    <label for="phone">Phone Number <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="phone" name="phone" autocomplete="tel" required>
  </div>

  <div class="field-container left-field">
    <label for="how_you_find">How you found me <span class="required" aria-hidden="true">*</span></label>
    <select id="how_you_find" name="how_you_find" required>
	  <option value="" disabled selected hidden>Select...</option>
			<option value="Google">Google/Search</option>
			<option value="AI">AI/ChatGPT/Gemini</option>
			<option value="Referral">Referral (Please specify below)</option>
			<option value="Other">Other (Please specify below)</option>
		</select>
  </div>

  <div class="field-container right-field">
    <label for="referal_name">Referral/Other:</label>
    <input type="text" id="referal_name" name="referal_name">
  </div>

	<div class="field-container clear">
		<label for="message">Your Message <span class="required" aria-hidden="true">*</span></label>
		<textarea id="message" name="message" rows="5" required></textarea>
	</div>

	<div class="field-container checkbox-container">
		<input name="consent" type="checkbox" required id="consent" value="yes">
		<label for="consent" style="font-size: 14px;">
			By checking this box and submitting this form, I consent to the collection and processing of the information provided, which may include Protected Health Information (PHI). I authorize this practice to contact me via email, phone, text message, or voicemail. I acknowledge and understand that standard email and text messaging are not secure or encrypted methods of communication. I accept the risks of communicating via unencrypted email and text message (including the risk of unauthorized access or interception by third parties) and explicitly request and consent to receive email and text communications from this practice regarding my inquiry or care. <span class="required" aria-hidden="true">*</span>
		</label>
	</div>
	
	<div class="cf-turnstile" data-sitekey="0x4AAAAAABewuznfN6LBlp7v" data-theme="light"></div>
	
  <button type="submit" id="submit-btn">Send Message</button>

  <p class="attribution"><a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign=mwt" target="_blank">HIPAA Compliant Contact Form</a></p>

</form>

<script>
	// Ensure the script runs only after the DOM is fully loaded
	document.addEventListener('DOMContentLoaded', function() {
	  const form = document.getElementById('contact-form');

	  if (!form) {
		console.error("Argon Pipeline Error: Could not find form element with ID 'contact-form'.");
		return;
	  }

	  form.addEventListener('submit', async function(e) {
		e.preventDefault();

		const submitBtn = document.getElementById('submit-btn');
		const originalBtnText = submitBtn ? submitBtn.innerText : 'Send Message';
		if (submitBtn) {
			submitBtn.disabled = true;
			submitBtn.innerText = 'Securing connection...';
		}

		try {
		  // 1. Safely capture the consent checkbox
		  const consentCheckbox = document.getElementById('consent');
		  if (!consentCheckbox || !consentCheckbox.checked) {
			alert("Please accept the communication consent agreement before submitting.");
			if (submitBtn) {
				submitBtn.disabled = false;
				submitBtn.innerText = originalBtnText;
			}
			return;
		  }

		  // Helper function to safely read field values
		  const getValue = (id) => {
			const el = document.getElementById(id);
			return el ? el.value.trim() : '';
		  };

		  // 2. Construct JSON payload safely
		  const formData = {
			first_name: getValue('first_name'),
			last_name: getValue('last_name'),
			email: getValue('email'),
			phone: getValue('phone'),
			how_you_find: getValue('how_you_find'),
			referal_name: getValue('referal_name'),
			message: getValue('message'),
			consent: consentCheckbox.checked ? 'yes' : 'no',
			fax_number: getValue('fax_number') // Honeypot field
		  };

		  // Capture Turnstile token if element exists
		  const turnstileInput = document.querySelector('[name="cf-turnstile-response"]');
		  if (turnstileInput && turnstileInput.value) {
			formData['cf-turnstile-response'] = turnstileInput.value;
		  }

		  // 3. Send payload to back-end container
		  const response = await fetch('/submit-form.php', {
			method: 'POST',
			headers: { 
			  'Content-Type': 'application/json',
			  'Accept': 'application/json'
			},
			body: JSON.stringify(formData)
		  });

		  const result = await response.json();

		  if (result.status === 'success') {
			// Hide the form
			form.style.display = 'none';

			// Reveal stylized HTML success container
			const successMessage = document.getElementById('success-message'); 
			if (successMessage) {
			  successMessage.style.display = 'block';

			  // Snap internal iframe viewport smoothly to the top
			  window.scrollTo({ top: 0, behavior: 'smooth' });

			  // Accessibility: focus message for screen readers
			  successMessage.focus();
			}

			// Notify parent host page to scroll iframe into view if embedded
			if (window.parent && window.parent !== window) {
			  window.parent.postMessage({ action: 'formSubmittedSuccess' }, '*');
			}

			// Reset form fields
			form.reset();
		  } else {
			alert(result.message || "A security or validation error occurred.");
			if (typeof turnstile !== 'undefined') turnstile.reset();
		  }

		} catch (err) {
		  console.error("Argon Pipeline JS Catch:", err);
		  alert("An internal system error prevented this message from sending. Please check browser console.");
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