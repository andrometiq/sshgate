#!/usr/bin/env bash
set -euo pipefail
mkdir -p /run/sshd /home/user/.ssh
chown -R user:user /home/user
chmod 0700 /home/user/.ssh
ssh-keygen -A
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=no -o UsePAM=no
