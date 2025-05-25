#!/bin/bash

echo "⏳ Waiting for PostgreSQL..."
until nc -zv "$POSTGRES_HOST" "$POSTGRES_PORT"; do
  echo "❌ PostgreSQL not ready. Retrying..."
  sleep 1
done

echo "✅ PostgreSQL is ready!"
echo "Applying database migrations..."

python manage.py makemigrations
python manage.py migrate

# Optional: merge if needed
# python manage.py makemigrations --merge

echo "🚀 Starting application..."
exec "$@"


