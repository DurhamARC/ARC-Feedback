#!/bin/bash
set -e

echo "Setting environment..."
# Set the environment variables in /etc/environment for use in login shells
# https://stackoverflow.com/a/34631891/1681205
env | egrep -v "^(APPSETTING_.+=|PATH=|HOME=|USER=|MAIL=|LC_ALL=|LS_COLORS=|LANG=|HOSTNAME=|PWD=|TERM=|SHLVL=|LANGUAGE=|_=)" >> /etc/environment

echo "Starting SSH ..."
service ssh start

echo "Starting nginx..."
nginx -t
touch /var/log/nginx/access.log /var/log/nginx/error.log
ln -sf /dev/stdout /var/log/nginx/access.log
ln -sf /dev/stderr /var/log/nginx/error.log
service nginx start

cd /app/SearchApp
<<<<<<< HEAD

flask db upgrade
=======
>>>>>>> 5665188 (Update Dockerfiles and WSGI to reference correct module from correct workdir)

# Add `--access-logfile '-' --log-level=debug \` for debugging
exec $@
