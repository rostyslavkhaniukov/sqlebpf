#!/bin/bash
set -e

mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

# Start PostgreSQL with TCP listener
docker-entrypoint.sh postgres -c listen_addresses='*' &
PG_PID=$!

# Wait for PostgreSQL to accept TCP connections
until pg_isready -h localhost -U postgres -q; do
    sleep 0.2
done

# Run tests
/test.bin -test.v -test.run TestE2E -test.count 1
TEST_EXIT=$?

# Stop PostgreSQL
kill $PG_PID 2>/dev/null
wait $PG_PID 2>/dev/null || true

exit $TEST_EXIT
