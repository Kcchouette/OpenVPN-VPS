# OpenVPN-VPS

Install OpenVPN on a new VPS and some tools (nano)

## Fork

This fork includes the following features:

- Choice for UDP or TCP (UDP is still recommended)
- No logs
- No comp-lzo as [compression is a vector for oracle attacks, e.g. CRIME or BREACH](https://github.com/BetterCrypto/Applied-Crypto-Hardening/pull/91#issuecomment-75388575)
- Better encryption (see below)
- Avoid DNS leak
- TLS 1.2 only
- Strong ciphers, DH keys and certificates keys.
- HMAC encrypted by AES-128-CBC or more, and SHA-512 (instead of BF-128-CBC and SHA1)
- Run server in unprivileged mode, reducing risks to the system
- TLS-auth support: it adds an additional HMAC signature to all SSL/TLS handshake packets for integrity verification thus allowing an additional level of security above and beyond that provided by SSL/TLS. [source](https://openvpn.net/index.php/open-source/documentation/howto.html#security) and provide a 2nd line of defense to the TLS channel.
- [FDN's DNS Servers](https://www.fdn.fr/actions/dns/)
- Nearest [OpenNIC DNS Servers](https://www.opennicproject.org/)
- [DNS.WATCH DNS Servers](https://dns.watch/index)
- What-you-want DNS (see [Recommended DNS provider](https://github.com/Kcchouette/OpenVPN-VPS/blob/master/Recommended_DNS_provider.md)
- Up-to-date OpenVPN (2.3.12) thanks to [swupdate.openvpn.net](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos)

## Variants

In this script, *fast* is still more secured than default OpenVPN settings.

**Note:** Both [NSA](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf) and [ANSSI](https://www.ssi.gouv.fr/uploads/2015/01/RGS_v-2-0_B1.pdf) recommend at least a 3072 bits for a future-proof key. As the size of the key will have an impact on speed, I leave the choice to use 2048, 3072 or 4096 bits RSA key. 4096 bits is what's most used and recommened today, but 3072 bits is still good.

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

Then give all the `.ovpn` to your client!

## Installation of openVPN for the client

See [INSTALL_OPENVPN.md](https://github.com/Kcchouette/OpenVPN-VPS/blob/master/INSTALL_OPENVPN.md)

## Test of how secure is your VPN

 * https://whoer.net/#extended
 * https://www.dnsleaktest.com/

## Based on:

- https://github.com/Nyr/openvpn-install/tree/b6f0c42b5b22bd57cc7536998c7dc871ace05237
- https://github.com/Angristan/OpenVPN-install/tree/63ed1449de27d7513c1bb58962f29a8aa1545fcb
