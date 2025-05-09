#!/bin/bash
set -e

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
gunicorn --workers 2 --timeout=20 \
         --log-file=- --bind=127.0.0.1:5000 wsgi:app
