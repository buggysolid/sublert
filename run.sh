#!/usr/bin/env bash

LOCK_FILE=/tmp/running.lock
SUBLERT=sublert-http
TIME_TO_SLEEP_IN_SECONDS=300

if [[ -f "$LOCK_FILE" ]]; then
  sleep 1
else
  # Using this as a jitter for cron
  sleep $((RANDOM % TIME_TO_SLEEP_IN_SECONDS))
  touch "$LOCK_FILE"
  cd $HOME/$SUBLERT
  source runtime/bin/activate
  python sublert.py
  rm -rf "$LOCK_FILE"
fi
