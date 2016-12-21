#!/bin/bash
# Secure OpenVPN server installer for Debian, Ubuntu

# This script will work on Debian, Ubuntu and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu box.

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

#check tun is available
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 3
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
		exit 4
	fi
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu system"
	exit 4
fi

#Build a new client
newclient () {
	#Generate a custom client.ovpn
	cp /etc/openvpn/client-template.txt ~/$1.ovpn
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
	IP=$(wget -qO- ipv4.icanhazip.com)
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
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "If your server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP address as it is. (local/private IP)"
	echo "Otherwise, it should be your public IPv4 address."
	read -p "IP address: " -e -i $IP IP

	echo "What protocol do you want for OpenVPN?"
	echo "Unless UDP is blocked, you should not use TCP (unnecessarily slower)"
	while [[ $PROTOCOL != "UDP" && $PROTOCOL != "TCP" ]]; do
		read -p "Protocol [UDP/TCP]: " -e -i UDP PROTOCOL
	done
	echo ""

	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT

	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo " 1) Current system resolvers"
	echo " 2) FDN (France)"
	echo " 3) OpenNIC (the nearest)"
	echo " 4) DNS.WATCH (Germany)"
	echo " 5) UncensoredDNS (Denmark)"
	echo " 6) OpenDNS"
	echo " 7) Google"
	echo " 8) Enter 2 other DNS (recommended)"
	
	read -p "DNS [1-8]: " -e -i 8 DNS

	echo "Choose which cipher you want to use for the data channel:"
	echo "   1) AES-128-CBC + AES-128-GCM-SHA256 (fastest)"
	echo "   2) AES-192-CBC + AES-256-CBC-SHA256 (recommended, best compromise)"
	echo "   3) AES-256-CBC + AES-256-GCM-SHA384 (most secure)"
	while [[ $CIPHER != "1" && $CIPHER != "2" && $CIPHER != "3" ]]; do
		read -p "Cipher [1-3]: " -e -i 2 CIPHER
	done
	case $CIPHER in
		1)
		CIPHER="cipher AES-128-CBC"
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"
		RSA_DIGEST="sha256"
		;;
		2)
		CIPHER="cipher AES-192-CBC"
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"
		RSA_DIGEST="sha256"
		;;
		3)
		CIPHER="cipher AES-256-CBC"
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"
		RSA_DIGEST="sha384"
		;;
	esac

	echo "Choose what size of Diffie-Hellman/RSA key you want to use:"
	echo "   1) 2048 bits (fastest)"
	echo "   2) 3072 bits (recommended, best compromise)"
	echo "   3) 4096 bits (most secure)"
	while [[ $KEY_SIZE != "1" && $KEY_SIZE != "2" && $KEY_SIZE != "3" ]]; do
		read -p "Key size [1-3]: " -e -i 2 KEY_SIZE
	done
	case $KEY_SIZE in
		1)
		KEY_SIZE="2048"
		;;
		2)
		KEY_SIZE="3072"
		;;
		3)
		KEY_SIZE="4096"
		;;
	esac

	read -p "Maximum Connections: " -e -i 5 MAXCONNS

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
		# Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
		# Then we install OpnVPN and some tools
		apt-get install openvpn iptables openssl wget ca-certificates curl nano -y
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
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

	# See https://github.com/OpenVPN/easy-rsa/blob/5a429d22c78604c95813b457a8bea565a39793fa/easyrsa3/easyrsa#L1015
	echo "set_var EASYRSA_KEY_SIZE $KEY_SIZE
set_var EASYRSA_DIGEST		"sha256"
set_var EASYRSA_DN		""org""
set_var EASYRSA_REQ_COUNTRY	"$CACOUNTRY"
set_var EASYRSA_REQ_PROVINCE	"$CAPROVINCE"
set_var EASYRSA_REQ_CITY	"$CACITY"
set_var EASYRSA_REQ_ORG		"$CAORG"
set_var EASYRSA_REQ_EMAIL	"$CAEMAIL"
set_var EASYRSA_REQ_OU		"$CAORG"
set_var EASYRSA_REQ_CN		"$CACN"
set_var EASYRSA_CA_EXPIRE	"365"
set_var EASYRSA_CERT_EXPIRE	"365"
" > vars
	fi

	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa gen-crl

	# Generate tls-auth key
	openvpn --genkey --secret /etc/openvpn/tls-auth.key

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" > /etc/openvpn/server.conf
	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "proto udp" >> /etc/openvpn/server.conf
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "proto tcp" >> /etc/openvpn/server.conf
	fi
	echo "dev tun
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
tls-version-min 1.2
tls-cipher $TLSCIPHER" >> /etc/openvpn/server.conf

	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf


	# DNS resolvers
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
		4) #DNS.WATCH 
		echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
		;;
		5) #UncensoredDNS 
		echo 'push "dhcp-option DNS 91.239.100.100"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 89.233.43.71"' >> /etc/openvpn/server.conf
		;;
		6) #OpenDNS 
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		7) #Google 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		8) #other DNS
		read -p "IP for DNS_1: " -e DNS_1
		read -p "IP for DNS_2: " -e DNS_2
		echo "push \"dhcp-option DNS $DNS_1\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS $DNS_2\"" >> /etc/openvpn/server.conf
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


	# Create the sysctl configuration file if needed (mainly for Arch Linux)
	if [[ ! -e $SYSCTL ]]; then
		touch $SYSCTL
	fi

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $SYSCTL
	if ! grep -q "\<net.ipv4.ip_forward\>" $SYSCTL; then
		echo 'net.ipv4.ip_forward=1' >> $SYSCTL
	fi

	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Set NAT for the VPN subnet
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL

	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port. Using both permanent and not permanent rules to
		# avoid a firewalld reload.
		if [[ "$PROTOCOL" = 'UDP' ]]; then
			firewall-cmd --zone=public --add-port=$PORT/udp
			firewall-cmd --permanent --zone=public --add-port=$PORT/udp
		elif [[ "$PROTOCOL" = 'TCP' ]]; then
			firewall-cmd --zone=public --add-port=$PORT/tcp
			firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
		fi
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	fi
	if iptables -L -n | grep -qE 'REJECT|DROP'; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		if [[ "$PROTOCOL" = 'UDP' ]]; then
			iptables -I INPUT -p udp --dport $PORT -j ACCEPT
		elif [[ "$PROTOCOL" = 'TCP' ]]; then
			iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
		fi
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		if [[ "$PROTOCOL" = 'UDP' ]]; then
			sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
		elif [[ "$PROTOCOL" = 'TCP' ]]; then
			sed -i "1 a\iptables -I INPUT -p tcp --dport $PORT -j ACCEPT" $RCLOCAL
		fi
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' ]]; then
				if [[ "$PROTOCOL" = 'UDP' ]]; then
					semanage port -a -t openvpn_port_t -p udp $PORT
				elif [[ "$PROTOCOL" = 'TCP' ]]; then
					semanage port -a -t openvpn_port_t -p tcp $PORT
				fi
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
	fi

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit/Scaleway users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
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

	# client-template.txt is created so we have a template to add further users later
	echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "proto tcp-client" >> /etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
setenv opt block-outside-dns
remote-cert-tls server
cipher $CIPHER
auth SHA512
tls-version-min 1.2
tls-client
tls-cipher $TLSCIPHER" >> /etc/openvpn/client-template.txt

	echo ""
	echo "Finished!"
	echo ""
	echo "If you want to add clients, you simply need to run this script another time!"
fi
