#!/usr/bin/env bash

set -o errexit
set -o pipefail

if [ "$EUID" -ne 0 ]
  then echo "Please run the script as root or invoke via sudo."
  exit
fi

if [[ -f "/usr/bin/apt" ]]; then
  apt update
  apt install -y git python3 cronie
elif [[ -f "/usr/bin/yum" ]]; then
  yum makecache
  yum install -y git python3 cronie
else
  echo "Could not determine which package manager is installed."
  exit
fi

systemctl enable crond && systemctl start crond