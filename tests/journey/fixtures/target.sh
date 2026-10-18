#!/usr/bin/env bash
set -euo pipefail
mkdir -p /run/sshd /home/user/.ssh
chown -R user:user /home/user
chmod 0700 /home/user/.ssh
printf 'enabled=0\n' > /home/user/health.conf
chown user:user /home/user/health.conf
runuser -u user -- python3 -u /opt/journey/fixtures/health.py > /home/user/health.log 2>&1 &
ssh-keygen -A
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=no -o UsePAM=no
