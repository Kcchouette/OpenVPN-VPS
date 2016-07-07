#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu

# This script will work on Debian, Ubuntu and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu box.

#check it's root
if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 1
fi

#check tun is available
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 2
fi

#check debian version
if [[ -e /etc/debian_version ]]; then
	OS="debian"
	#We get the version number, to verify we can get a recent version of OpenVPN
	VERSION_ID=$(cat /etc/*-release | grep "VERSION_ID")
	RCLOCAL='/etc/rc.local'
	if [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="12.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="15.10"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]]; then
		echo "Your version of Debian/Ubuntu is not supported. Please look at the documentation."
		exit 4
	fi
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu system"
	exit 4
fi

#Build a new client
newclient () {
	#Generate a custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "key-direction 1" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/tls-auth.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (LowEndSpirit/Scaleway)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- canihazip.com/s)
fi


if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo " 1) Add a cert for a new user"
		echo " 4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1) 
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, certs available at ~/$CLIENT.ovpn"
			exit
			;;
			4) exit;;
		esac
	done
else
	clear # OpenVPN setup and first user creation
	echo 'Welcome to this quick OpenVPN installer'
	echo ""
	echo "First, choose which variant of the script you want to use."
	echo '"Fast" is secure, but "slow" is the best encryption you can get, at the cost of speed (not that slow though)'
	echo " 1) Fast (2048 bits RSA and DH, 128 bits AES)"
	echo " 2) Slow (4096 bits RSA and DH, 256 bits AES)"
	while [[ $VARIANT != "1" && $VARIANT != "2" ]]; do
		read -p "Variant [1-2]: " -e -i 2 VARIANT
	done

	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "If you server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP adress as it is. (local/private IP"
	echo "Otherwise, it sould be your public IPv4 address."
	read -p "IP address: " -e -i $IP IP

	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT

	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo " 1) Current system resolvers"
	echo " 2) FDN (recommended)"
	echo " 3) OpenNIC"
	echo " 4) DNS.WATCH"
	echo " 5) OpenDNS"
	echo " 6) Google"
	read -p "DNS [1-6]: " -e -i 2 DNS

	echo ""
	echo "Some setups (e.g. Amazon Web Services), require use of MASQUERADE rather than SNAT"
	echo "Which forwarding method do you want to use [if unsure, leave as default]?"
	echo " 1) SNAT (default)"
	echo " 2) MASQUERADE"
	while [[ $FORWARD_TYPE != "1" && $FORWARD_TYPE != "2" ]]; do
		read -p "Forwarding type: " -e -i 1 FORWARD_TYPE
	done

	#INPUT MAX CONNECTIONS
	read -p "Maximum Connections: " -e -i 5 MAXCONNS

	#INPUT DEFAULT DOMAIN
	echo ""
	read -p "(Optional) Enter a Default Domain: " -e -i example.com DOMAIN1
	echo ""
	#END DEFAULT DOMAIN

	echo "Input CA Parameters:"
	#INPUT CA PARAMETERS
	read -p "CA Country: " -e -i US CACOUNTRY
	#printf "$CACOUNTRY\n"
	read -p "CA Province: " -e -i California CAPROVINCE
	#printf "$CAPROVINCE\n"
	read -p "CA City: " -e -i "San Francisco" CACITY
	#printf "$CACITY\n"
	read -p "CA ORG: " -e -i "Example Co" CAORG
	#printf "$CAORG\n"
	read -p "CA Email: " -e -i info@example.com CAEMAIL
	#printf "$CAEMAIL\n"
	read -p "CA OU: " -e -i "My Organization" CAOU
	#printf "$CAOU\n"
	read -p "CA CN: " -e -i "My Name" CACN
	#printf "$CACN\n"
	#END CA INPUT
	echo ""
	echo "Okay, we are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."

	if [[ "$OS" = 'debian' ]]; then
		apt-get install ca-certificates -y

		# We add the OpenVPN repo to get the latest version.
		# Debian 7
		if [[ "$VERSION_ID" = 'VERSION_ID="7"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt wheezy main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Debian 8
		if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt jessie main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt update
		fi
		# Ubuntu 12.04
		if [[ "$VERSION_ID" = 'VERSION_ID="12.04"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt precise main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu 14.04
		if [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt trusty main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# The repo, is not available for Ubuntu 15.10 and 16.04, but it has OpenVPN > 2.3.3, so we do nothing

		# Then we install OpnVPN and some tools
		apt-get install openvpn iptables openssl wget ca-certificates curl ufw nano -y
	fi

	ufw allow ssh
	ufw enable

	# find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
  	NOGROUP=nogroup
	else
  	NOGROUP=nobody
	fi

	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	# Get easy-rsa from Github
	wget -O ~/EasyRSA-3.0.1.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/

	# If the user selected the fast, less hardened version
	if [[ "$VARIANT" = '1' ]]; then
		echo "set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_DIGEST "sha256"
set_var EASYRSA_DN	""org""
set_var EASYRSA_REQ_COUNTRY	"$CACOUNTRY"
set_var EASYRSA_REQ_PROVINCE	"$CAPROVINCE"
set_var EASYRSA_REQ_CITY	"$CACITY"
set_var EASYRSA_REQ_ORG		"$CAORG"
set_var EASYRSA_REQ_EMAIL	"$CAEMAIL"
set_var EASYRSA_REQ_OU		"$CAORG"
set_var EASYRSA_REQ_CN		"$CACN"
" > vars
	fi

	# If the user selected the relatively slow, ultra hardened version
	if [[ "$VARIANT" = '2' ]]; then
		echo "set_var EASYRSA_KEY_SIZE 4096
set_var EASYRSA_KEY_SIZE 4096
set_var EASYRSA_DIGEST "sha384"
set_var EASYRSA_DN	""org""
set_var EASYRSA_REQ_COUNTRY	"$CACOUNTRY"
set_var EASYRSA_REQ_PROVINCE	"$CAPROVINCE"
set_var EASYRSA_REQ_CITY	"$CACITY"
set_var EASYRSA_REQ_ORG		"$CAORG"
set_var EASYRSA_REQ_EMAIL	"$CAEMAIL"
set_var EASYRSA_REQ_OU		"$CAORG"
set_var EASYRSA_REQ_CN		"$CACN"
" > vars
	fi

	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa gen-crl

	# generate tls-auth key
	openvpn --genkey --secret /etc/openvpn/tls-auth.key

	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT
proto udp
dev tun
max-clients $MAXCONNS
ca ca.crt
cert server.crt
key server.key
dh dh.pem
user nobody
group $NOGROUP
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
cipher AES-256-CBC
auth SHA512
tls-version-min 1.2" > /etc/openvpn/server.conf

	if [[ "$VARIANT" = '1' ]]; then
		# If the user selected the fast, less hardened version
		echo "tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256" >> /etc/openvpn/server.conf
	elif [[ "$VARIANT" = '2' ]]; then
		# If the user selected the relatively slow, ultra hardened version
		echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> /etc/openvpn/server.conf
	fi

	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf

  	# DHCP OPTIONS
	if [[ "$DOMAIN1" != "" ]]; then
		echo "push \"dhcp-option DOMAIN $DOMAIN1\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option SEARCH $DOMAIN1\"" >> /etc/openvpn/server.conf
	fi

	# DNS
	case $DNS in
		1) 
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) #FDN
		echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server.conf
		;;
		3) #OpenNIC
		#Getting the nearest OpenNIC servers using the geoip API
		read ns1 ns2 <<< $(curl -s https://api.opennicproject.org/geoip/ | head -2 | awk '{print $1}')
		echo "push \"dhcp-option DNS $ns1\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS $ns2\"" >> /etc/openvpn/server.conf
		;;
		5) #DNS.WATCH 
		echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
		;;
		5) #OpenDNS 
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		6) #Google 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
	esac

	echo "remote-cert-eku \"TLS Web Client Authentication\"
	keepalive 10 120
persist-key
persist-tun
crl-verify crl.pem
tls-server
tls-auth tls-auth.key 0
verb 0" >> /etc/openvpn/server.conf

	# Enable net.ipv4.ip_forward for the system
	if [[ "$OS" = 'debian' ]]; then
		sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	fi

	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Set NAT for the VPN subnet
	if [[ "$FORWARD_TYPE" = '1' ]]; then
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	else
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE" $RCLOCAL
	fi
	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port. Using both permanent and not permanent rules to
		# avoid a firewalld reload.
		firewall-cmd --zone=public --add-port=$PORT/udp
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		if [[ "$FORWARD_TYPE" = '1' ]]; then		
			firewall-cmd --zone=trusted --add-masquerade
			firewall-cmd --permanent --zone=trusted --add-masquerade
		fi
	elif ufw status | grep -qw active; then
		ufw allow $PORT/udp
		if [[ "$FORWARD_TYPE" = '1' ]]; then
			sed -i '1s/^/##OPENVPN_START\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0\/24 -o eth0 -j MASQUERADE\nCOMMIT\n##OPENVPN_END\n\n/' /etc/ufw/before.rules
			sed -ie 's/^DEFAULT_FORWARD_POLICY\s*=\s*/DEFAULT_FORWARD_POLICY="ACCEPT"\n#before openvpn: /' /etc/default/ufw
		fi
	fi
	if iptables -L | grep -qE 'REJECT|DROP'; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		iptables -I INPUT -p udp --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p udp $PORT
			fi
		fi
	fi

	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit/Scaleway users
	EXTERNALIP=$(wget -qO- canihazip.com/s)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit, Scaleway, or behind a router),"
		echo "then I need to know the address that can be used to access it from outside."
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP or domain name: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi

	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto udp
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA512
setenv opt block-outside-dns
tls-version-min 1.2
tls-client" > /etc/openvpn/client-common.txt

	if [[ "$VARIANT" = '1' ]]; then
		# If the user selected the fast, less hardened version
		echo "tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256" >> /etc/openvpn/client-common.txt
	elif [[ "$VARIANT" = '2' ]]; then
		# If the user selected the relatively slow, ultra hardened version
		echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> /etc/openvpn/client-common.txt
	fi

	echo ""
	echo "Finished!"
	echo ""
	echo "If you want to add clients, you simply need to run this script another time!"
fi
