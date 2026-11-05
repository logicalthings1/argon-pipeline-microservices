#!/usr/bin/env bash
set -euo pipefail

PROJECT="mercury-499921"
REGION="us-central1"
DRY_RUN=false
REQUESTED_SERVICES=()

# Canonical service registry: name|source_directory|health_check_url
ALL_SERVICES=(
  "argon-form|$HOME/argon-form|https://argon.argonpipeline.com"
  "marian-form|$HOME/marian-form|https://mwt.argonpipeline.com"
  "nwhs-form|$HOME/nwhs-form|https://nwhs.argonpipeline.com"
  "rugeleydds-form|$HOME/rugeleydds-form|https://rugeleydds.argonpipeline.com"
  # REGISTRY_ANCHOR
)

# Extract registered service names dynamically
REGISTERED_NAMES=()
for entry in "${ALL_SERVICES[@]}"; do
  [[ "$entry" =~ ^[[:space:]]*# ]] && continue
  REGISTERED_NAMES+=("${entry%%|*}")
done

# Parse CLI options and arguments
for arg in "$@"; do
  case "$arg" in
    --dry-run|-d)
      DRY_RUN=true
      ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [service1 service2 ...]"
      echo ""
      echo "Available services:"
      for name in "${REGISTERED_NAMES[@]}"; do
        echo "  - $name"
      done
      echo ""
      echo "If no service names are supplied, all services will be deployed."
      exit 0
      ;;
    -*)
      echo "Error: Unknown option '$arg'"
      echo "Run '$0 --help' for usage."
      exit 1
      ;;
    *)
      REQUESTED_SERVICES+=("$arg")
      ;;
  esac
done

if [ "$DRY_RUN" = true ]; then
  echo ">>> RUNNING IN DRY-RUN MODE: No changes will be deployed or deleted."
fi

echo "=========================================================="
echo " Zero-Cost Multi-Tenant Cloud Run Deployment Pipeline     "
echo " Project: $PROJECT | Region: $REGION                 "
echo "=========================================================="

# Determine target service list
SERVICES_TO_DEPLOY=()
if [ ${#REQUESTED_SERVICES[@]} -eq 0 ]; then
  for entry in "${ALL_SERVICES[@]}"; do
    [[ "$entry" =~ ^[[:space:]]*# ]] && continue
    SERVICES_TO_DEPLOY+=("$entry")
  done
else
  for req in "${REQUESTED_SERVICES[@]}"; do
    MATCH_FOUND=false
    for entry in "${ALL_SERVICES[@]}"; do
      [[ "$entry" =~ ^[[:space:]]*# ]] && continue
      IFS="|" read -r svc_name svc_dir svc_url <<< "$entry"
      if [ "$req" == "$svc_name" ]; then
        SERVICES_TO_DEPLOY+=("$entry")
        MATCH_FOUND=true
        break
      fi
    done
    if [ "$MATCH_FOUND" = false ]; then
      echo "Error: Unknown service '$req'."
      echo "Valid services are: ${REGISTERED_NAMES[*]}"
      exit 1
    fi
  done
fi

# Deploy each selected service
for entry in "${SERVICES_TO_DEPLOY[@]}"; do
  IFS="|" read -r svc_name svc_dir svc_url <<< "$entry"

  echo ""
  echo "----------------------------------------------------------"
  echo ">>> Service: $svc_name"
  echo "    Source Dir: $svc_dir"
  echo "----------------------------------------------------------"

  if [ ! -d "$svc_dir" ]; then
    echo "Error: Directory '$svc_dir' does not exist."
    exit 1
  fi

  # 1. PHP Syntax Validation
  echo "Validating PHP syntax..."
  while IFS= read -r -d '' php_file; do
    php -l "$php_file" > /dev/null
  done < <(find "$svc_dir" -maxdepth 2 -type f -name "*.php" -print0)
  echo "PHP syntax check PASSED."

  # 2. Deployment
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Simulated: gcloud run deploy $svc_name --region=$REGION --source=."
  else
    (cd "$svc_dir" && gcloud run deploy "$svc_name" \
      --project="$PROJECT" \
      --region="$REGION" \
      --source=. \
      --quiet)
  fi

  # 3. Production Health Check
  echo ">>> Running health check on production endpoint..."
  if [ "$DRY_RUN" = true ]; then
    HTTP_CODE=$(curl -s -L -o /dev/null -w "%{http_code}" "$svc_url" || echo "000")
  else
    sleep 3
    HTTP_CODE=$(curl -s -L -o /dev/null -w "%{http_code}" "$svc_url" || echo "000")
  fi

  if [ "$HTTP_CODE" == "200" ]; then
    echo ">>> Health check PASSED: $svc_url responded with HTTP 200"
  else
    echo ">>> Health check WARNING: $svc_url returned HTTP $HTTP_CODE"
  fi
done

# Post-Deployment Maintenance
echo ""
echo "=========================================================="
echo " Post-Deployment Free-Tier Maintenance Run                "
echo "=========================================================="

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Simulated: Image retention enforcement (keeping 2 newest per service)."
  echo "[DRY-RUN] Simulated: GCS source staging bucket purge."
else
  # Enforce image retention for deployed services
  for entry in "${SERVICES_TO_DEPLOY[@]}"; do
    IFS="|" read -r svc_name svc_dir svc_url <<< "$entry"
    REPO="us-central1-docker.pkg.dev/$PROJECT/cloud-run-source-deploy/$svc_name"
    
    OLD_DIGESTS=$(gcloud artifacts docker images list "$REPO" \
      --sort-by="~CREATE_TIME" --format="value(DIGEST)" 2>/dev/null | sed -e '1,2d' || true)

    if [ -n "$OLD_DIGESTS" ]; then
      for digest in $OLD_DIGESTS; do
        gcloud artifacts docker images delete "$REPO@$digest" --quiet --delete-tags 2>/dev/null || true
      done
    fi
  done

  # Purge Cloud Build tarball archives from Google Cloud Storage
  gsutil -m rm -r "gs://${PROJECT}_cloudbuild/source/**" 2>/dev/null || true
fi

echo ""
echo "Execution finished successfully."
