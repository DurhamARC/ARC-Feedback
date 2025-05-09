#!/bin/bash
set -e

echo "Setting environment..."
# Set the environment variables in /etc/environment for use in login shells
# https://stackoverflow.com/a/34631891/1681205
env | egrep -v "^(PATH=|HOME=|USER=|MAIL=|LC_ALL=|LS_COLORS=|LANG=|HOSTNAME=|PWD=|TERM=|SHLVL=|LANGUAGE=|_=)" >> /etc/environment

echo "Starting SSH ..."
service ssh start

echo "Starting nginx..."
nginx -t
touch /var/log/nginx/access.log /var/log/nginx/error.log
ln -sf /dev/stdout /var/log/nginx/access.log
ln -sf /dev/stderr /var/log/nginx/error.log
service nginx start

cd /app/

# Add `--access-logfile '-' --log-level=debug \` for debugging
exec gunicorn \
        --workers 2 --timeout=20 \
        --log-file=- --bind=127.0.0.1:5000 \
        wsgi:app
