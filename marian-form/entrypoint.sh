#!/bin/sh
# Copy the secret .env file if it exists
if [ -f /secrets/.env ]; then
  cp /secrets/.env /var/www/html/.env
fi
# Start Apache normally
exec apache2-foreground
