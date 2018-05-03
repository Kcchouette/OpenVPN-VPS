#!/bin/bash
# Secure OpenVPN server installer for Debian, Ubuntu

# This script will work on Debian, Ubuntu and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu box.

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
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
	echo "TUN is not available
You need to enable TUN before running this script"
	exit 3
fi

#check debian version
if [[ -e /etc/debian_version ]]; then
	OS="debian"
	# Getting the version number, to verify that a recent version of OpenVPN is available
	VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
	RCLOCAL='/etc/rc.local'
	SYSCTL='/etc/sysctl.conf'
	if [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="9"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="17.10"' ]]; then
		echo "Your version of Debian/Ubuntu is not supported. Please look at the documentation."
		exit 4
	fi
else
	echo "Looks like you aren't running this installer on Debian or Ubuntu"
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

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo
		echo "What do you want to do?"
		echo " 1) Create a new user"
		echo " 2) Revoke an existing user"
		echo " 4) Exit"
		read -p "Select an option [1-4]: " option

		case $option in
			1)
			echo
			echo "Tell me a name for the client config file"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo
			echo "Client $CLIENT added, config file available at ~/$CLIENT.ovpn"
			exit
			;;
			2)
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 6
			fi
			echo
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			./easyrsa gen-crl
			rm -f pki/reqs/$CLIENT.req
			rm -f pki/private/$CLIENT.key
			rm -f pki/issued/$CLIENT.crt
			rm -f /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo
			echo "Certificate for client $CLIENT revoked"
			echo "Exiting..."
			exit
			;;
			4) exit;;
		esac
	done
else
	clear # OpenVPN setup and first user creation
	echo 'Welcome to this OpenVPN installer!'

	echo
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "If your server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP address as it is. (local/private IP)"
	echo "Otherwise, it should be your public IPv4 address."
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		read -p "Public IP address / hostname: " -e PUBLICIP
	fi
	echo
	
	echo
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
	echo
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac

	echo
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT

	echo
	echo "Which DNS do you want to use with the VPN?"
	echo " 1) Current system resolvers (using IPs in /etc/resolv.conf)"
	echo " 2) FDN (France)"
	echo " 3) OpenNIC (the nearest)"
	echo " 4) Cloudflare"
	echo " 5) OpenDNS"
	echo " 6) Google"
	echo " 7) Enter 2 other DNS (recommended)"
	
	read -p "DNS [1-7]: " -e -i 7 DNS

	echo "Choose which RSA Digest you want to use to authentificate ssl connection"
	echo "   1) sha256 (fastest)"
	echo "   2) sha384"
	echo "   3) sha512 (most secure, recommended)"
	while [[ $RSA_DIGEST != "1" && $RSA_DIGEST != "2" && $RSA_DIGEST != "3" ]]; do
		read -p "RSA Digest [1-3]: " -e -i 3 RSA_DIGEST
	done
	case $RSA_DIGEST in
		1)
		RSA_DIGEST="sha256"
		;;
		2)
		RSA_DIGEST="sha384"
		;;
		3)
		RSA_DIGEST="sha512"
		;;
	esac	

	echo "Choose what size of Diffie-Hellman/RSA certificates/keys you want to use:"
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

	echo "Choose which cipher you want to use for the control channel:"
	echo "   1) TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 (fastest)"
	echo "   2) TLS-DHE-RSA-WITH-AES-256-CBC-SHA256 (recommended, best compromise)"
	echo "   3) TLS-DHE-RSA-WITH-AES-256-GCM-SHA384 (most secure)"
	while [[ $TLSCIPHER != "1" && $TLSCIPHER != "2" && $TLSCIPHER != "3" ]]; do
		read -p "TLS Cipher [1-3]: " -e -i 2 TLSCIPHER
	done
	case $TLSCIPHER in
		1)
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"
		;;
		2)
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"
		;;
		3)
		TLSCIPHER="TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"
		;;
	esac

	echo "Choose which cipher you want to use for the data channel:"
	echo "   1) AES-128-CBC (fastest)"
	echo "   2) AES-192-CBC (recommended, best compromise)"
	echo "   3) AES-256-CBC (most secure)"
	while [[ $CIPHER != "1" && $CIPHER != "2" && $CIPHER != "3" ]]; do
		read -p "Cipher [1-3]: " -e -i 2 CIPHER
	done
	case $CIPHER in
		1)
		CIPHER="AES-128-CBC"
		;;
		2)
		CIPHER="AES-192-CBC"
		;;
		3)
		CIPHER="AES-256-CBC"
		;;
	esac

	read -p "Maximum Connections: " -e -i 5 MAXCONNS

	echo
	echo "Okay, we are ready to set up your OpenVPN server now."
	read -n1 -r -p "Press any key to continue..."

	if [[ "$OS" = 'debian' ]]; then
		apt-get install ca-certificates gpg -y

		# We add the OpenVPN repo to get the latest version.
		# Debian 7
		if [[ "$VERSION_ID" = 'VERSION_ID="7"' ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable wheezy main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Debian 8
		if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt update
		fi
		# Ubuntu 12.04
		if [[ "$VERSION_ID" = 'VERSION_ID="12.04"' ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable precise main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu 14.04
		if [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable trusty main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
		# Then we install OpnVPN and some tools
		#apt-get update && apt-get upgrade
		apt-get install ca-certificates openvpn iptables openssl wget curl nano -y
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
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/

	# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	SERVER_NAME="server_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"

	# See https://github.com/OpenVPN/easy-rsa/blob/5a429d22c78604c95813b457a8bea565a39793fa/easyrsa3/easyrsa#L1015
	echo "set_var EASYRSA_KEY_SIZE $KEY_SIZE" > vars
	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars
	echo "set_var EASYRSA_DIGEST $RSA_DIGEST" >> vars

	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full $SERVER_NAME nopass
	./easyrsa gen-crl

	# Generate tls-auth key
	openvpn --genkey --secret /etc/openvpn/tls-auth.key

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key pki/crl.pem /etc/openvpn

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "local $IP
port $PORT
proto $PROTOCOL
dev tun
max-clients $MAXCONNS
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
dh dh.pem
user nobody
group $NOGROUP
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
cipher $CIPHER
auth SHA512
tls-version-min 1.2
tls-cipher $TLSCIPHER" > /etc/openvpn/server.conf

	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf


	# DNS resolvers
	case $DNS in
		1)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) # FDN
		echo "push \"dhcp-option DNS 80.67.169.12\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS 80.67.169.40\"" >> /etc/openvpn/server.conf
		;;
		3) # OpenNIC
		   # Getting the nearest OpenNIC servers using the geoip API
		read ns1 ns2 <<< $(curl -s https://api.opennicproject.org/geoip/ | head -2 | awk '{print $1}')
		echo "push \"dhcp-option DNS $ns1\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS $ns2\"" >> /etc/openvpn/server.conf
		;;
		4) # Cloudflare
		echo "push \"dhcp-option DNS 1.1.1.1\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS 1.0.0.1\"" >> /etc/openvpn/server.conf
		;;
		5) # OpenDNS 
		echo "push \"dhcp-option DNS 208.67.222.222\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS 208.67.220.220\"" >> /etc/openvpn/server.conf
		;;
		6) # Google 
		echo "push \"dhcp-option DNS 8.8.8.8\"" >> /etc/openvpn/server.conf
		echo "push \"dhcp-option DNS 8.8.4.4\"" >> /etc/openvpn/server.conf
		;;
		7) # Other DNS
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

	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL

		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24

		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
	else
		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL

		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL

		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
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

	# If the server is behind a NAT, use the correct IP address
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $PROTOCOL
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
setenv opt block-outside-dns
remote-cert-tls server
verify-x509-name $SERVER_NAME name
cipher $CIPHER
auth SHA512
tls-version-min 1.2
tls-client
tls-cipher $TLSCIPHER" > /etc/openvpn/client-template.txt

	echo
	echo "Finished!"
	echo
	echo "If you want to add clients, you simply need to run this script again!"
fi
