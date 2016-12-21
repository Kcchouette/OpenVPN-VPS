#!/bin/bash

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

#check it's root
if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

#check debian version
if [[ -e /etc/debian_version ]]; then
	OS="debian"
	# Getting the version number, to verify that a recent version of OpenVPN is available
	VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
	RCLOCAL='/etc/rc.local'
	SYSCTL='/etc/sysctl.conf'
	if [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="12.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.10"' ]]; then
		echo "Your version of Debian/Ubuntu is not supported. Please look at the documentation."
		exit 3
	fi
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu system"
	exit 3
fi

apt-get install unbound -y 
service unbound stop
unbound -c /etc/unbound/unbound.conf
unbound-anchor -a "/var/lib/unbound/root.key"

echo "server:
interface: 127.0.0.1
access-control: 127.0.0.1 allow
port: 53
do-daemonize: yes
num-threads: 2
use-caps-for-id: yes
harden-glue: yes
hide-identity: yes
hide-version: yes
qname-minimisation: yes" >> /etc/unbound/unbound.conf

service unbound start

#Allow the modification of the file
chattr -i /etc/resolv.conf

#Disable previous DNS servers
sed -i 's|nameserver|#nameserver|' /etc/resolv.conf
#Set localhost as the DNS resolver
echo "nameserver 127.0.0.1" >> /etc/resolv.conf

#Disallow the modification of the file
chattr +i /etc/resolv.conf

echo "The installation is done."
