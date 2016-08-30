# OpenVPN-VPS
Install OpenVPN on a new VPS and some tools

## Fork
This fork includes the following features:
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
- [FDN's DNS Servers](https://www.fdn.fr/actions/dns/)
- Nearest [OpenNIC DNS Servers](https://www.opennicproject.org/)
- [DNS.WATCH DNS Servers](https://dns.watch/index)
- Up-to-date OpenVPN (2.3.12) thanks to [swupdate.openvpn.net](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos)
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

## Installation
**You have to enable the TUN module otherwise OpenVPN won't work.** If the TUN module is not enabled, the script will tell you. Ask your host if you don't know how to do it.

Then download the script, run it and follow the assistant:

```
wget https://raw.githubusercontent.com/Kcchouette/OpenVPN-VPS/master/openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Once it ends, you should run it again to add users:
```
./openvpn-install.sh
```

## Based on:
- https://github.com/Nyr/openvpn-install/tree/dab9a210c2a57f4401ab3dacd8c1efce16e5dec2
- https://github.com/Angristan/OpenVPN-install/tree/2ce510aef5950e52fc83fbff5704204f78a480f4
- https://github.com/dwarnaka/OpenVPN-install/tree/2854fca5952f7c413dc259f8199b44a35ae461f0
