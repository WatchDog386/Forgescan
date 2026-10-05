#!/bin/sh
# Response agent for a protected host. It is the ONLY command the "responder" account may run.
#
# Install on the protected host (as root):
#   1. nft add table inet ainidr
#      nft add set inet ainidr blocked '{ type ipv4_addr; flags timeout; }'
#      nft add chain inet ainidr input '{ type filter hook input priority -10; }'
#      nft add rule inet ainidr input ip saddr @blocked drop
#   2. Copy this file to /usr/local/sbin/response-agent.sh and make it executable.
#   3. Allow the account to run it as root, and nothing else, in /etc/sudoers.d/responder:
#        responder ALL=(root) NOPASSWD: /usr/local/sbin/response-agent.sh
#   4. In ~responder/.ssh/authorized_keys, force the command for the AI-NIDR key:
#        command="sudo /usr/local/sbin/response-agent.sh",no-port-forwarding,no-pty ssh-ed25519 AAAA...
#
# The entries in the set expire by themselves, so a block ends even if AI-NIDR is switched off.
set -eu

# With a forced command, what the caller asked for arrives in SSH_ORIGINAL_COMMAND.
set -- ${SSH_ORIGINAL_COMMAND:-"$@"}
action="${1:-}"; ip="${2:-}"; minutes="${3:-30}"

# Accept nothing but a plain IPv4 address and a whole number of minutes.
echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || { echo "bad address" >&2; exit 2; }
echo "$minutes" | grep -Eq '^[0-9]{1,4}$' || { echo "bad duration" >&2; exit 2; }

case "$action" in
  block)   nft add element inet ainidr blocked "{ $ip timeout ${minutes}m }" ;;
  unblock) nft delete element inet ainidr blocked "{ $ip }" 2>/dev/null || true ;;
  *)       echo "unknown action" >&2; exit 2 ;;
esac
