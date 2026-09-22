#!/usr/bin/env bash
# Envelock — is the standby keeping up? Run on either server.
set -euo pipefail
role="$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()')"
if [ "$role" = "f" ]; then
  echo "This is the LIVE server. Standbys streaming from it:"
  sudo -u postgres psql -P pager=off -c "SELECT client_addr AS standby, state,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)) AS behind_by,
    COALESCE(replay_lag::text, 'caught up') AS lag
    FROM pg_stat_replication"
  sudo -u postgres psql -P pager=off -c "SELECT slot_name, active,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS wal_kept
    FROM pg_replication_slots"
  [ -n "$(sudo -u postgres psql -tAc 'SELECT 1 FROM pg_stat_replication')" ] \
    || { echo "!! no standby is connected"; exit 1; }
else
  echo "This is a STANDBY."
  sudo -u postgres psql -P pager=off -c "SELECT status,
    sender_host AS live_server,
    COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())::int || 's', 'n/a')
      AS last_change_copied_ago
    FROM pg_stat_wal_receiver"
  [ "$(sudo -u postgres psql -tAc "SELECT status FROM pg_stat_wal_receiver")" = "streaming" ] \
    || { echo "!! not streaming from the live server"; exit 1; }
fi
