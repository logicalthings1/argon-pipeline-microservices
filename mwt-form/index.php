cd ~ && git --no-pager diff _template-form/index.php && \
git add _template-form/index.php && \
git commit -m "Sync _template-form/index.php with updated Sen font and layout" && \
git push origin main && \
echo "=== Current HTML Email Template (submit-form.php) ===" && \
sed -n '85,175p' ~/lpd-form/submit-form.php