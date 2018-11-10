# OpenVPN-VPS

Install OpenVPN on a new VPS and some tools (nano).

## Fork

This fork includes the following features:

- Choice for UDP or TCP (UDP is still recommended)
- No logs
- No comp-lzo as [compression is a vector for oracle attacks, e.g. CRIME or BREACH](https://github.com/BetterCrypto/Applied-Crypto-Hardening/pull/91#issuecomment-75388575)
- Better encryption (see below)
- Avoid DNS leak
- Run server in unprivileged mode, reducing risks to the system
- Up-to-date OpenVPN thanks to [swupdate.openvpn.net](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos)
- No [internal networking](https://github.com/Nyr/openvpn-install/commit/6d51476047d6d7a610f292f9bbd6da75d2d8f96e)
- Keep the [official 180 days of certif](https://github.com/Nyr/openvpn-install/commit/9c0579052f149dd46cc59b1b8bee53f3d54dc785)
- Randomized certificate name

- [FDN's DNS Servers](https://www.fdn.fr/actions/dns/)
- Nearest [OpenNIC DNS Servers](https://www.opennicproject.org/)
- [Cloudflare DNS](https://1.1.1.1/)
- What-you-want DNS (see [Recommended DNS provider](https://github.com/Kcchouette/OpenVPN-VPS/blob/master/Recommended_DNS_provider.md))

- TLS 1.2 only
- TLS-auth support: it adds an additional HMAC signature to all SSL/TLS handshake packets for integrity verification thus allowing an additional level of security above and beyond that provided by SSL/TLS. [source](https://openvpn.net/index.php/open-source/documentation/howto.html#security) and provide a 2nd line of defense to the TLS channel.

- tls-auth check that all incoming packets have a valid signature (using SHA512)
- Securely negotiate a VPN connection using the PKI (Diffie-Hellman exchange with RSA key) = from 2048 to 4096 -> it allows Perfect Forward Secrecy (with Handshake). Diffie-Hellman key and RSA key are the same size because of easy-RSA
- Authentificate SSL connection using SHA-2 family (sha-256 to sha-512)
- Encypt data through the AES-128 or AES-256 cipher
- Encrypt control channel (network parameters and key material for the 'data channel') using TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 or more

**Note:** Both [NSA](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf) and [ANSSI](https://www.ssi.gouv.fr/uploads/2015/01/RGS_v-2-0_B1.pdf) recommend at least a 3072 bits for a future-proof key. As the size of the key will have an impact on speed, I leave the choice to use 2048, 3072 or 4096 bits RSA key. 4096 bits is what's most used and recommended today, but 3072 bits is still good.

## Compatibility

The script is made to work on these OS:

- Debian 9

## Installation

**You have to enable the TUN module otherwise OpenVPN won't work.** If the TUN module is not enabled, the script will tell you. Ask your host if you don't know how to do it.

**Update your OS before running this script!**

```
apt-get update
apt-get upgrade
```

Then download the script, run it and follow the assistant:

```
wget "https://raw.githubusercontent.com/Kcchouette/OpenVPN-VPS/master/openvpn-install.sh" --no-check-certificate
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

- https://github.com/Nyr/openvpn-install/tree/c90989a0e2dbb6316e5d048f105c8615f70c6ba9
- https://github.com/Angristan/OpenVPN-install/tree/5501de73c8742bef58aa62685ca4c898cae2e616
