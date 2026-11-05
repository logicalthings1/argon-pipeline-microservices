# Ensure production server is running php:8.4-apache
FROM php:8.4-apache

# Use official production php.ini base
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

# Inject security & privacy settings into PHP conf.d
RUN { \
    echo "display_errors = Off"; \
    echo "display_startup_errors = Off"; \
    echo "log_errors = On"; \
    echo "zend.exception_ignore_args = On"; \
    echo "log_errors_max_len = 1024"; \
} > $PHP_INI_DIR/conf.d/security-hardening.ini

# Copy application source code
COPY . /var/www/html/

# Reconfigure Apache to listen on Cloud Run's default port 8080
RUN sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf /etc/apache2/sites-available/*.conf

EXPOSE 8080