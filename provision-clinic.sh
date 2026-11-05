#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo "    Argon Pipeline - Clinic Provisioning Wizard   "
echo "=================================================="

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "mercury-499921")
REGION="us-central1"
TEMPLATE_DIR="$HOME/_template-form"

if [ ! -d "$TEMPLATE_DIR" ]; then
  echo "Error: Master template directory not found at $TEMPLATE_DIR"
  exit 1
fi

# 1. Clinic Metadata
read -rp "Clinic Display Name (e.g. Summit Dental): " CLINIC_NAME
read -rp "Clinic Subdomain Slug (e.g. summit): " CLINIC_SLUG

# Sanitize slug
CLINIC_SLUG=$(echo "$CLINIC_SLUG" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
SERVICE_NAME="${CLINIC_SLUG}-form"
CUSTOM_DOMAIN="${CLINIC_SLUG}.argonpipeline.com"
TARGET_DIR="$HOME/${SERVICE_NAME}"

if [ -d "$TARGET_DIR" ]; then
  echo "Error: Directory $TARGET_DIR already exists. Aborting."
  exit 1
fi

echo ""
echo "Creating instance at: $TARGET_DIR"
echo "Target domain: $CUSTOM_DOMAIN"
echo ""

# 2. Turnstile Setup
echo "--- Cloudflare Turnstile Configuration ---"
read -rp "Turnstile Site Key (public): " TURNSTILE_SITE_KEY
read -rsp "Turnstile Secret Key (hidden): " TURNSTILE_SECRET_KEY
echo ""

# 3. Mail Transport Selection
echo ""
echo "--- Mail Dispatch Mechanism ---"
echo "  1) Microsoft Graph API (Microsoft 365 / OAuth 2.0)"
echo "  2) PHPMailer SMTP (Google Workspace / Standard SMTP)"
read -rp "Select driver [1 or 2]: " DRIVER_CHOICE

# Helper function to create or update secrets safely
upsert_secret() {
  local secret_name="$1"
  local secret_value="$2"

  if gcloud secrets describe "$secret_name" --project="$PROJECT_ID" >/dev/null 2>&1; then
    printf "%s" "$secret_value" | gcloud secrets versions add "$secret_name" --data-file=- --project="$PROJECT_ID" >/dev/null
    echo "  Updated existing secret: $secret_name"
  else
    printf "%s" "$secret_value" | gcloud secrets create "$secret_name" --data-file=- --replication-policy="automatic" --project="$PROJECT_ID" >/dev/null
    echo "  Created new secret: $secret_name"
  fi
}

TURNSTILE_SECRET_NAME="${SERVICE_NAME}-turnstile-secret"
echo ""
echo "Saving Turnstile secret in Secret Manager..."
upsert_secret "$TURNSTILE_SECRET_NAME" "$TURNSTILE_SECRET_KEY"

if [ "$DRIVER_CHOICE" = "1" ]; then
  MAIL_DRIVER="graph"
  echo ""
  echo "--- Microsoft Graph API Configuration ---"
  read -rp "Azure Tenant ID: " MS_TENANT_ID
  read -rp "Azure Client / App ID: " MS_CLIENT_ID
  read -rsp "Azure Client Secret (hidden): " MS_CLIENT_SECRET
  echo ""
  read -rp "Sender Mailbox (e.g. info@clinic.com): " SENDER_EMAIL
  read -rp "Recipient Address(es) (comma-separated): " RECIPIENT_EMAIL
  read -rp "BCC Address(es) (optional, press Enter to skip): " BCC_EMAIL

  MAIL_SECRET_NAME="${SERVICE_NAME}-ms-secret"
  echo "Saving Azure Client Secret in Secret Manager..."
  upsert_secret "$MAIL_SECRET_NAME" "$MS_CLIENT_SECRET"

  ENV_VARS="MAIL_DRIVER=graph,CLINIC_NAME=${CLINIC_NAME},TURNSTILE_SITE_KEY=${TURNSTILE_SITE_KEY},MS_TENANT_ID=${MS_TENANT_ID},MS_CLIENT_ID=${MS_CLIENT_ID},SENDER_EMAIL=${SENDER_EMAIL},RECIPIENT_EMAIL=${RECIPIENT_EMAIL}"
  if [ -n "$BCC_EMAIL" ]; then
    ENV_VARS="${ENV_VARS},BCC_EMAIL=${BCC_EMAIL}"
  fi
  SECRETS="MS_CLIENT_SECRET=${MAIL_SECRET_NAME}:latest,TURNSTILE_SECRET_KEY=${TURNSTILE_SECRET_NAME}:latest"

else
  MAIL_DRIVER="smtp"
  echo ""
  echo "--- Google Workspace / SMTP Configuration ---"
  read -rp "SMTP Host [smtp.gmail.com]: " SMTP_HOST
  SMTP_HOST="${SMTP_HOST:-smtp.gmail.com}"
  read -rp "SMTP Port [465]: " SMTP_PORT
  SMTP_PORT="${SMTP_PORT:-465}"
  read -rp "SMTP Username / User (e.g. contact@clinic.com): " SMTP_USER
  read -rsp "SMTP App Password (hidden): " SMTP_PASS
  echo ""
  read -rp "Sender Email [${SMTP_USER}]: " SENDER_EMAIL
  SENDER_EMAIL="${SENDER_EMAIL:-$SMTP_USER}"
  read -rp "Recipient Address(es) (comma-separated): " RECIPIENT_EMAIL
  read -rp "BCC Address(es) (optional, press Enter to skip): " BCC_EMAIL

  MAIL_SECRET_NAME="${SERVICE_NAME}-smtp-pass"
  echo "Saving SMTP password in Secret Manager..."
  upsert_secret "$MAIL_SECRET_NAME" "$SMTP_PASS"

  ENV_VARS="MAIL_DRIVER=smtp,CLINIC_NAME=${CLINIC_NAME},TURNSTILE_SITE_KEY=${TURNSTILE_SITE_KEY},SMTP_HOST=${SMTP_HOST},SMTP_PORT=${SMTP_PORT},SMTP_USER=${SMTP_USER},SENDER_EMAIL=${SENDER_EMAIL},RECIPIENT_EMAIL=${RECIPIENT_EMAIL}"
  if [ -n "$BCC_EMAIL" ]; then
    ENV_VARS="${ENV_VARS},BCC_EMAIL=${BCC_EMAIL}"
  fi
  SECRETS="SMTP_PASS=${MAIL_SECRET_NAME}:latest,TURNSTILE_SECRET_KEY=${TURNSTILE_SECRET_NAME}:latest"
fi

# 4. Clone Template & Replace Placeholders
echo ""
echo "Cloning template files to $TARGET_DIR..."
cp -r "$TEMPLATE_DIR" "$TARGET_DIR"

# Replace placeholders in index.php
sed -i "s|{{CLINIC_NAME}}|${CLINIC_NAME}|g" "$TARGET_DIR/index.php"
sed -i "s|{{CLINIC_SLUG}}|${CLINIC_SLUG}|g" "$TARGET_DIR/index.php"

# 5. Build and Deploy Cloud Run Service
echo ""
echo "Deploying Cloud Run service: $SERVICE_NAME..."
gcloud run deploy "$SERVICE_NAME" \
  --source "$TARGET_DIR" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars="$ENV_VARS" \
  --set-secrets="$SECRETS"

# 6. Create Domain Mapping
echo ""
echo "Mapping domain: $CUSTOM_DOMAIN -> $SERVICE_NAME..."
gcloud beta run domain-mappings create \
  --service "$SERVICE_NAME" \
  --domain "$CUSTOM_DOMAIN" \
  --region "$REGION" \
  --project "$PROJECT_ID" || echo "Domain mapping command completed (may already exist)."

echo ""
echo "=================================================="
echo "           Clinic Provisioning Complete!          "
echo "=================================================="
echo "Service Name : $SERVICE_NAME"
echo "Custom Domain: https://$CUSTOM_DOMAIN"
echo ""
echo "1. DNS Requirement:"
echo "   Create a CNAME record at your DNS provider (Cloudflare):"
echo "   Type : CNAME"
echo "   Name : $CLINIC_SLUG"
echo "   Value: ghs.googlehosted.com."
echo "   Proxy: DNS Only (Gray Cloud)"
echo ""
echo "2. Iframe Embed Code for Client Website:"
cat << HTML
<iframe 
  src="https://${CUSTOM_DOMAIN}/" 
  width="100%" 
  height="700" 
  frameborder="0" 
  style="border:none; max-width:600px; width:100%; display:block;"
  title="Contact Us - ${CLINIC_NAME}">
</iframe>
HTML
echo ""
echo "3. Remember to add the following line to deploy-all.sh if desired:"
echo "   \"$SERVICE_NAME|\$HOME/$SERVICE_NAME|https://$CUSTOM_DOMAIN\""
echo "=================================================="
