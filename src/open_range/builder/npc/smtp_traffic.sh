#!/usr/bin/env bash
# Level 0 NPC: SMTP traffic generator (benign mail loop)
#
# Simulates normal internal mail activity so Blue sees routine mail events
# mixed in with attack traffic. Works both inside the mail container and
# against a remote SMTP service.
#
# Environment variables:
#   MAIL_HOST    - hostname of the mail server (default: mail)
#   RATE_LAMBDA  - messages per minute (default: 6)

set -euo pipefail

MAIL_HOST="${MAIL_HOST:-mail}"
RATE_LAMBDA="${RATE_LAMBDA:-6}"
INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

send_via_sendmail() {
    local sender="notifications@corp.local"
    local recipient="ops@corp.local"
    local subject="Routine status update"
    {
        echo "From: ${sender}"
        echo "To: ${recipient}"
        echo "Subject: ${subject}"
        echo
        echo "Nightly maintenance completed successfully."
    } | /usr/sbin/sendmail -t >/dev/null 2>&1 || true
}

send_via_smtp() {
    {
        echo "HELO corp.local"
        echo "MAIL FROM:<notifications@corp.local>"
        echo "RCPT TO:<ops@corp.local>"
        echo "DATA"
        echo "Subject: Routine status update"
        echo
        echo "Nightly maintenance completed successfully."
        echo "."
        echo "QUIT"
    } | nc "${MAIL_HOST}" 25 >/dev/null 2>&1 || true
}

echo "[NPC-SMTP] Starting SMTP traffic to ${MAIL_HOST} at ${RATE_LAMBDA} msgs/min"

while true; do
    if [ -x /usr/sbin/sendmail ]; then
        send_via_sendmail
    else
        send_via_smtp
    fi
    sleep "${INTERVAL}"
done
