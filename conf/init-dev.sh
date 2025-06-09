#!/bin/sh
# Development init.sh file for Docker 

i=1
MAX_TRIES=100

# Check if required environment variables are set
if [ -z "$DB_USER" ] || \
   [ -z "$DB_PASS" ] || \
   [ -z "$DB_NAME" ] || \
   [ -z "$POSTGRES_HOST" ] || \
   [ -z "$POSTGRES_PORT" ];
then
    echo "Error: One or more required environment variables are not set."
    echo "Exiting."
    exit 1
fi

# Wait for database ready
until PGPASSWORD=${DB_PASS} PGPORT=${POSTGRES_PORT} pg_isready -h ${POSTGRES_HOST} -U ${DB_USER} -d ${DB_NAME} >/dev/null 2>&1; do
  echo "Waiting for database on $POSTGRES_HOST:$POSTGRES_PORT... Attempt $i/$MAX_TRIES";
  
  i=$((i+1))
  if [ "$i" -gt "$MAX_TRIES" ]; then
      exit 1
  fi

  sleep 2
done;

#flask db init
flask db upgrade

exec $@
