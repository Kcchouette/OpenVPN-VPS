# How to install the OpenVPN software?

## Browser

I recommend using Tor Brwser, that is a Mozilla hardening, but by [removing the Tor features of this browser](https://superuser.com/a/1117660):

 - Upper right hand side of Tor Browser click on the three horizontal bars, click on **Preferences**, select the **Advanced** tab, click on **Network**, click on **Settings**, select **"No Proxy"** and hit OK.
 - Upper right hand side of Tor Browser click on the three horizontal bars, click on **Add-ons**, choose **Disable** at the right of *Torbutton* and *TorLauncher*.
 - Then type "about:config" into the url bar, go to "network.proxy.socks_remote_dns" right click and select Toggle (after that, the value should be **false**).
  - At that point your browser won´t be using TOR proxy to access to the internet, but if you also want to disable the TOR service running in the background type "about:config" into the url bar, go to "extensions.torlauncher.start_tor", right click and select Toggle (after that, the value should be **false**).

----
* Platforms
  * [Windows](#windows)
  * [OS X](#os-x)
  * [GNU/Linux](#gnulinux)
  * [Linux (Network-manager)](#gnulinux-networkmanager)
  * [Android](#android)
  * [iOS](#ios)

## Windows

1. Download and run the OpenVPN [Windows Installer][windows_url].
1. Click *Next* and accept the license agreement by selecting *I Agree*.
1. Click *Next* on the *Choose Components* screen. Leave all of the default options checked.
1. Make note of the Destination Folder. This is where you will place the `.ovpn` client configuration profile after installation. Click *Install*.
1. A Windows Security notice will appear and ask *Would you like to install this device software?*. Click *Install*.
1. Click *Next* on the *Installation Complete* screen.
1. Uncheck *Show Readme* and click *Finish*.
1. Right-click on the OpenVPN GUI desktop icon and choose *Properties*.
1. Go to the *Compatibility* tab and click the *Run this program as an administrator* checkbox in the *Privilege Level* section.
1. Double-click the OpenVPN GUI desktop icon to launch the application.
1. Download your `.ovpn` file.
1. Open the *config* directory that is located in the Destination Folder. For most users, this will either be in *C:\Program Files\OpenVPN\config* or *C:\Program Files (x86)\OpenVPN\config*. You will see a single README file in this directory.
1. Drag and drop the downloaded `.ovpn` file to this location alongside the README.
1. Right-click on the OpenVPN icon in your taskbar and choose *Connect*.
1. You will see a log scroll by as the connection is established, followed by a taskbar notification indicating your assigned IP.
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.


## OS X

1. Download and open [Tunnelblick][osx_url].
1. Type your password to allow the installation process to complete, and click *OK*.
1. Click *Launch* after the installation is finished.
1. Click *I have configuration files*.
1. Download your `.ovpn` file.
1. Double-click this file.
1. You will be asked to choose whether the profile should be available for all users or only the current user. After making your selection, you will be asked to enter your password.
1. Look for the Tunnelblick icon in your menu bar. Click on it, and choose *Connect*.
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.


## GNU/Linux

1. Install OpenVPN:

   `sudo apt-get install openvpn` OR `sudo yum install openvpn` OR `esoteric-package-manager hipster openvpn`

   * If installing OpenVPN via your package manager is not an option, you can also download and compile the [OpenVPN source code][openvpn_sourcecode].
1. Download your `.ovpn` file.
1. Copy the downloaded `.ovpn` file to the location of your choice. */etc/openvpn/* is a decent option.
1. On some distributions, the pushed DHCP DNS option from the OpenVPN server will be ignored. This means that your DNS queries will still be routed through your ISP's servers which makes them vulnerable to what is known as a DNS leak.
**To avoid that**, for example Ubuntu come with script: just update `/etc/nsswitch.conf` and only keep *dns* in front of *hosts*; and add at the end of you `.ovpn` file something like: `script-security 2 \ up /etc/openvpn/update-resolv-conf \ down /etc/openvpn/update-resolv-conf`
1. Execute OpenVPN, and pass it the .ovpn profile as an option.
   `sudo openvpn --config [your .ovpn file]`
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.


## GNU/Linux (NetworkManager)

This method is very risky as there is some DNS leaks…

1. First, download your `.ovpn` file.
1. Install the OpenVPN plugin for NetworkManager.

   `sudo apt-get install network-manager-openvpn network-manager-openvpn-gnome`
1. Open your *System Settings*.
1. Click the *Network* icon.
1. Click the *+* button in the lower-left of the window.
1. Select *VPN* from the Interface drop-down and click *Import*.
1. Navigate to your `.ovpn` file and select it.
1. Select the VPN in the left-hand menu, and flip the switch to *ON*. You can also enable/disable the VPN by clicking on the WiFi/Network icon in the menu bar, scrolling to *VPN Connections*, and clicking on its name.
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.


## Android

1. Install [OpenVPN for Android][openvpn_android].
1. Download your `.ovpn` file.
1. Copy the `.ovpn` file to your phone.
1. Launch OpenVPN for Android.
1. Tap the folder icon in the lower-right of the screen.
1. Select the `.ovpn` profile that you copied to your phone.
1. Tap the save icon (floppy disk) in the lower-right of the screen after the import is complete.
1. Tap the profile.
1. Accept the Android VPN connection warning.
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.


## iOS

1. Download [OpenVPN Connect][openvpn_ios] and launch it.
1. Download your `.ovpn` file.
1. Open iTunes on your computer and connect your phone.
1. Select your phone, click on the *Apps* tab, and find OpenVPN under the *File Sharing* section.
1. Drag and drop the downloaded `.ovpn` file into the file sharing window.
1. OpenVPN on your phone will say that *1 new OpenVPN profile is available for import*.
1. Tap the green *+* button to import the profile.
1. Tap the slider to connect to the OpenVPN server.
1. Success! You can verify that your traffic is being routed properly by [looking up your IP address here][check_ip]. It should show different informations than yours.

[check_ip]: https://www.whatismyip.com/my-ip-information/
[windows_url]: https://swupdate.openvpn.org/community/releases/openvpn-install-2.4.6-I602.exe
[osx_url]: https://tunnelblick.net/release/Latest_Tunnelblick_Stable.dmg
[openvpn_sourcecode]: https://swupdate.openvpn.org/community/releases/openvpn-2.4.4.tar.gz
[openvpn_android]: https://play.google.com/store/apps/details?id=de.blinkt.openvpn
[openvpn_ios]: https://itunes.apple.com/us/app/openvpn-connect/id590379981
