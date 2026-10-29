FROM php:8.2-apache
RUN a2enmod rewrite headers
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html
EXPOSE 8080
ENV PORT=8080
RUN sed -i 's/80/8080/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf
