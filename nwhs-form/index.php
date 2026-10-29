<?php
// 1. Grab environment domains
$allowed_env = getenv('CLIENT_DOMAIN') ?: 'https://www.nwhsmiles.com';

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
  <meta charset="utf-8">
  <title>Secure Contact Form</title>
	<style>
		body {
			margin-left: 0px;
			margin-top: 0px;
			margin-right: 0px;
			margin-bottom: 0px;
		}
		form, div {font-family: adelle-sans, Helvetica, Arial, sans-serif}
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
			width: 48%;
			float: left;
			margin-right: 10px;
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
			background: #93dded;
			fill: #93dded;
			color: #000000;
			border-color: #93dded;
			font-family: adelle-sans, Helvetica, Arial, sans-serif;
			font-size: 1.1em;
			font-weight: 400;
			line-height: 1em;
			border-style: solid;
			border-width: 2px;
			border-radius: 40px;
			padding: 10px 25px;
			margin-top: 15px;
			cursor: pointer;
		}
		button:hover {background: #A7E1ED; color: #000000;}
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
				width: 47%;
			}
			.right-field {
				width:47%;
			}
		}
    </style>
</head>

<body>

<!-- ACCESSIBLE SUCCESS MESSAGE -->
<div id="success-message" role="status" aria-live="polite" tabindex="-1" style="display: none; background-color: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; padding: 25px; border-radius: 4px; text-align: center; max-width: 500px; margin: 0 auto;">
    <h3 style="margin-top: 0;">Message Sent Securely</h3>
    <p style="margin-bottom: 0;">Thank you! Your secure message has been received. We will get back to you shortly.</p>
</div>
	
<form id="argon-secure-form" style="max-width: 100%; margin: 0 auto;">

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
    <label for="how_you_find">How you found us <span class="required" aria-hidden="true">*</span></label>
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
	
  <button type="submit" id="submit-btn">Send Message</button>

  <p class="attribution"><a href="https://argonpipeline.com/?utm_source=website&utm_medium=footer&utm_campaign=nwhs" target="_blank">HIPAA Compliant Contact Form</a></p>

</form>

<script>
document.getElementById('argon-secure-form').addEventListener('submit', async function(e) {
    e.preventDefault();

    // --- CONSENT VALIDATION BLOCK ---
    const consentBox = document.getElementById('consent');
    if (!consentBox.checked) {
        alert("Please check the consent box to proceed.");
        return; // This stops the script from continuing
    }
    // -----------------------------------------
    
    const form = e.target;
    const btn = document.getElementById('submit-btn');
    btn.disabled = true;
    btn.innerText = 'Securing connection...';

    try {
        // Dynamically package the form data into JSON
        const formData = new FormData(form);
        const formObject = Object.fromEntries(formData.entries());

        const submitResponse = await fetch('/submit-form.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formObject)
        });
        
        // UPGRADE: Parse the JSON response directly
        const res = await submitResponse.json();

		// Check the JSON status directly
        if (submitResponse.ok && res.status === 'success') {
            
            // HIDE FORM AND SHOW SUCCESS MESSAGE
			form.style.display = 'none';
			const successDiv = document.getElementById('success-message');
			successDiv.style.display = 'block';

			// Snap iframe viewport to top
			window.scrollTo({ top: 0, behavior: 'smooth' });

			// ACCESSIBILITY: Move focus to the new message
			successDiv.focus();

        } else {
            alert(res.message || 'Your submission failed. Please contact info@nwhsmiles.com.');
            console.error('Server Debug Info:', res);
            if (typeof turnstile !== 'undefined') turnstile.reset();
        }

    } catch (error) {
        alert('A secure connection error occurred. Please try again.');
        console.error('Frontend Error Tracking:', error);
        if (typeof turnstile !== 'undefined') turnstile.reset();
    } finally {
        btn.disabled = false;
        btn.innerText = 'Send Message';
    }
});
</script>

</body>

</html>