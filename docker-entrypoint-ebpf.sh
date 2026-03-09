#!/bin/bash
set -e

mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

# Запускаємо PostgreSQL у фоні через оригінальний entrypoint
echo "[*] Starting PostgreSQL..."
/usr/local/bin/docker-entrypoint.sh "$@" &
PG_PID=$!

# Чекаємо поки PostgreSQL стане ready
echo "[*] Waiting for PostgreSQL to be ready..."
until pg_isready -U postgres -q 2>/dev/null; do
    sleep 0.5
done

# Запускаємо sqlray у фоні
echo "[*] Starting sqlray..."
stdbuf -oL /usr/local/bin/sqlray &
SQL_TRACER_PID=$!

# Обробляємо сигнали для коректного завершення
trap "kill $SQL_TRACER_PID $PG_PID 2>/dev/null; wait" SIGTERM SIGINT

# Чекаємо на PostgreSQL — якщо він завершиться, завершуємо все
wait $PG_PID
kill $SQL_TRACER_PID 2>/dev/null
