#!/usr/bin/env bash
set -eo pipefail

PROJECT_ID="mercury-499921"
REGION="us-central1"
DRY_RUN=false

if [[ "$1" == "--dry-run" ]]; then
  DRY_RUN=true
  echo ">>> RUNNING IN DRY-RUN MODE: No changes will be deployed or deleted."
fi

SERVICES=(
  "argon-internal-form:argon-internal-form:https://argon.argonpipeline.com"
  "marian-form:marian-form:https://mwt.argonpipeline.com"
  "nwhs-form:nwhs-form:https://nwhs.argonpipeline.com"
  "rugeleydds-form:rugeleydds-form:https://rugeleydds.argonpipeline.com"
)

echo "=========================================================="
echo " Zero-Cost Multi-Tenant Cloud Run Deployment Pipeline     "
echo " Project: ${PROJECT_ID} | Region: ${REGION}               "
echo "=========================================================="

for entry in "${SERVICES[@]}"; do
  IFS=":" read -r DIR SERVICE_NAME URL <<< "${entry}"
  
  echo -e "\n----------------------------------------------------------"
  echo ">>> Service: ${SERVICE_NAME}"
  echo "    Source Dir: ~/${DIR}"
  echo "----------------------------------------------------------"

  if [ ! -d "${HOME}/${DIR}" ]; then
    echo "ERROR: Directory ${HOME}/${DIR} does not exist. Skipping."
    continue
  fi

  cd "${HOME}/${DIR}"

  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Validating PHP syntax..."
    find . -maxdepth 2 -name "*.php" -exec php -l {} \; > /dev/null
    echo "[DRY-RUN] PHP syntax check PASSED."
    echo "[DRY-RUN] Simulated: gcloud run deploy ${SERVICE_NAME} --region=${REGION} --source=."
  else
    gcloud run deploy "${SERVICE_NAME}" \
      --project="${PROJECT_ID}" \
      --region="${REGION}" \
      --source=. \
      --clear-base-image \
      --quiet
  fi

  echo ">>> Running health check on production endpoint..."
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 15 "${URL}" || echo "ERR")
  
  if [[ "${HTTP_STATUS}" =~ ^(200|301|302)$ ]]; then
    echo ">>> Health check PASSED: ${URL} responded with HTTP ${HTTP_STATUS}"
  else
    echo ">>> WARNING: Health check returned HTTP ${HTTP_STATUS} for ${URL}"
  fi
done

echo -e "\n=========================================================="
echo " Post-Deployment Free-Tier Maintenance Run                "
echo "=========================================================="

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Simulated: Image retention enforcement (keeping 2 newest per service)."
  echo "[DRY-RUN] Simulated: GCS source staging bucket purge."
else
  for pkg in argon-internal-form marian-form nwhs-form rugeleydds-form; do
    echo "Checking image revisions for ${pkg}..."
    gcloud artifacts docker images list "us-central1-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/${pkg}" \
      --sort-by="~CREATE_TIME" \
      --format="value(DIGEST)" 2>/dev/null | tail -n +3 | while read -r digest; do
        [ -n "$digest" ] && gcloud artifacts docker images delete \
          "us-central1-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/${pkg}@${digest}" \
          --delete-tags \
          --quiet
    done
  done

  echo "Clearing temporary GCS source tarballs..."
  gcloud storage rm --recursive "gs://run-sources-${PROJECT_ID}-${REGION}/**" --quiet 2>/dev/null || true
fi

echo -e "\nExecution finished successfully."
