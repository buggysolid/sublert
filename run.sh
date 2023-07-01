#!/usr/bin/env bash

LOCK_FILE=/tmp/running.lock
SUBLERT=sublert-http

if [[ -f "$LOCK_FILE" ]]; then
  sleep 1
else
  touch "$LOCK_FILE"
  cd $HOME/$SUBLERT
  source runtime/bin/activate
  python sublert.py
  rm -rf "$LOCK_FILE"
fi