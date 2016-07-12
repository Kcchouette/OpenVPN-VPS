# OpenVPN-VPS
Install OpenVPN on a new VPS and some tools

##Fork
This fork includes :
- No logs
- No comp-lzo [compression is a vector for oracle attacks, e.g. CRIME or BREACH](https://github.com/BetterCrypto/Applied-Crypto-Hardening/pull/91#issuecomment-75388575)
- Better encryption (see below)
- Avoid DNS leak
- UFW support
- TLS 1.2 only
- Strong ciphers, DH keys and certificates. (see variants)
- AES-256-CBC and SHA-512 for HMAC (instead of BF-128-CBC and SHA1)
- Run server in unprivileged mode, reducing risks to the system
- TLS-auth to help [thwart DoS attacks](https://openvpn.net/index.php/open-source/documentation/howto.html#security) and provide a 2nd line of defense to the TLS channel.
- [FDN's DNS Servers](http://www.fdn.fr/actions/dns/)
- Nearest [OpenNIC DNS Servers](https://www.opennicproject.org/)
- [DNS.WATCH DNS Servers](https://dns.watch/index)
- Up-to-date OpenVPN (2.3.11) thanks to [swupdate.openvpn.net](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos)
- Support for either SNAT or MASQUERADE for forwarding

## Variants
When you lauch the script you will be asked to choose a mode. Both will work the same way, but *slow* has higher encryption settings, so it may slow down your connection and take more time to install.

If you're just using your VPN at home, you may choose *fast*. But if you're often using public Wi-Fi or traveling a lot, you choose use *slow*.

FYI, *fast* is still more secured than default OpenVPN settings.

### Slow (high encryption)
Features:
- 4096 bits RSA private key
- 4096 bits Diffie-Hellman key
- 256 bits AES-GCM
- SHA-384 RSA certificate

### Fast (lower encryption)
Features:
- 2048 bits RSA private key
- 2048 bits Diffie-Hellman key
- 128 bits AES-GCM
- SHA-256 RSA certificate

## Compatibility
The script is made to work on these OS :
- Debian 8

##Installation
Run the script and follow the assistant:

```
wget https://raw.githubusercontent.com/Kcchouette/OpenVPN-VPS/master/openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Once it ends, you should run it again to add users.

##Based on:
- https://github.com/Nyr/openvpn-install/tree/ef1ae85797fa4d1bf456adff45f759e169c4bf8d
- https://github.com/Angristan/OpenVPN-install/commit/66c78333f512d523611a4c443b161ca9bd32b1ce
- https://github.com/dwarnaka/OpenVPN-install/tree/2854fca5952f7c413dc259f8199b44a35ae461f0
