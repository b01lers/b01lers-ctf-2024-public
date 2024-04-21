FROM php:8.3-apache

COPY ./src /var/www/html/

COPY flag.txt /flag.txt

RUN mkdir /var/www/html/tmp/
RUN chmod 777 /var/www/html/tmp/

EXPOSE 80
