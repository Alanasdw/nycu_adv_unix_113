#!/bin/sh

#
# usage: /entrypoint.sh <username> <password> <uid> <gid>
#

_USER=${1:-upclass}
_PASS=${2:-password}
_UID=${3:-1000}
_GID=${4:-1000}

# create the user if it does not exist
if ! id -u $_USER; then
	groupadd -g $_GID $_USER
	useradd --uid $_UID --gid $_GID --groups root,sudo,adm,users --create-home --shell /bin/bash $_USER
	echo "$_USER:$_PASS" | chpasswd
fi	

exec /usr/sbin/sshd -D
