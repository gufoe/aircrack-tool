# Aircrack Tool
Just select the wifi you want to crack, and the tool will:
- disable network-manager
- enable a monitor interface through airmon-ng
- start capturing packets untill an handshake is received (airodump-ng)
- reset network (removing monitor interfaces and restarting network-manager)
Does not pretend to be a great tool, just to save a few minutes.
Open to suggestions/push requests/whatever.

## Installation
```npm install aircrack-tool```

## Usage:
```
Usage: airtool flags <command>
  Flags:
    -i interface: interface on which activate airmon (default wlan0)
    -d, --deauth: enables active attack: deauthenticate clients to force a new handshake
  Commands:
    --reset: to use in case of errors/interruption of the process, removes monitor interfaces and (re)starts the network-manager
    --help: display this help
```
