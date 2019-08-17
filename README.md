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

- Some DNS choices: [FDN's DNS Servers](https://www.fdn.fr/actions/dns/), Nearest [OpenNIC DNS Servers](https://www.opennicproject.org/), [Cloudflare DNS](https://1.1.1.1/), [Quad9 uncensored DNS](https://quad9.net/doh-quad9-dns-servers/#UsingDoHwithQuad9DNSServers-AdditionalInformation)
- What-you-want DNS (see [Recommended DNS provider](https://github.com/Kcchouette/OpenVPN-VPS/blob/master/Recommended_DNS_provider.md))

- TLS 1.2 only
- TLS-crypt support: tls-crypt will add an additional HMAC signature to all SSL/TLS handshake packets for integrity verification and it'll also encrypt the TLS control channel.

- auth check that all incoming packets have a valid signature (using SHA512)
- Securely negotiate a VPN connection using the PKI (Diffie-Hellman exchange with ECDSA key)
- Authentificate SSL connection using SHA-2 family (sha-512)
- Encypt data through the AES-128-GCM / AES-192-GCM / AES-256-GCM cipher
- Encrypt control channel (network parameters and key material for the 'data channel') using TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 or more

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

Then give the `.ovpn` file to your client!

## Installation of openVPN for the client

See [INSTALL_OPENVPN.md](https://github.com/Kcchouette/OpenVPN-VPS/blob/master/INSTALL_OPENVPN.md)

## Test of how secure is your VPN

 * https://whoer.net/#extended
 * https://www.dnsleaktest.com/

## Based on:

- https://github.com/Nyr/openvpn-install/tree/d4efae3b1081867ffce420267f8c20a7c7336047
- https://github.com/angristan/openvpn-install/tree/a0685af1a32f7a5729abcd9dbda1e08dfa4e75ab
