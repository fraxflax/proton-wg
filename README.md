# proton-wg
proton-wg.sh - ProtonVPN Linux Client WireGuard interface setup script

brings down/up an ProtonVPN WireGuard interface and sets up the routing and dns via it 
 
proton-wg.sh must be run as root

proton-wg.sh is free software written by Fredrik Ax &lt;proton-wg@axnet.nu&gt;<br>
Feel free to modify and/or (re)distribute it in any way you like.
(It's always nice to be mentioned though ;-) )

proton-wg.sh comes with ABSOLUTELY NO WARRANTY.

If you expirence any problems with proton-wg.sh, are lacking any
functionality or just want to voice your opions about it, feel free
to contact me via e-mail: Fredrik Ax &lt;proton-wg@axnet.nu&gt;<br>
(also, if you need a script for setting up a Linux router to route 
certain subnets via ProtonVPN, feel free to contact me)

## INSTALL
Just copy / download the `proton-wg.sh` script into your PATH and make it executable:<br>
https://raw.githubusercontent.com/fraxflax/proton-wg/refs/heads/main/proton-wg.sh

From CLI:
```
curl -o /usr/local/bin/proton-wg.sh https://raw.githubusercontent.com/fraxflax/proton-wg/refs/heads/main/proton-wg.sh
chmod a+rx /usr/local/bin/proton-wg.sh
```

# USAGE

## NAME
__proton-wg.sh__ - ProtonVPN Linux Client WireGuard interface setup script

## SYNOPSIS

__proton-wg.sh__ [ --verbose | --debug ] down

__proton-wg.sh__ [ --verbose | --debug ] up <ins>CC</ins> [ rand | <ins>INDEX</ins> | rtt | <ins>CONFIGFILE</ins> ] [ dns ]

## DESCRIPTION

This script selects among config files that have been generated at

  https://account.proton.me/vpn/WireGuard

and downloaded to `/etc/wireguard/` named: `wgp[a-z]{2}[0-9a-z]+.conf`
where `[a-z]{2}` is the two letter contrycode and `[0-9a-z]+` is the <ins>INDEX</ins>
using the selected config to bring up an wireguard Proton VPN.

OBSERVE that you need to edit the config files commenting out the
Address line and the DNS line:
```
  #Address = 10.2.0.2/32
  #DNS = 10.2.0.1
```

BUT do not remove the lines, they are expected to be in the file,
just commented out without whitespace after the #

Examples of of valid config filenames:
```
/etc/wireguard/wgpuk142.conf
/etc/wireguard/wgpch42tor.conf
```


 ## OPTIONS

  * __--verbose | --debug__<br>
    Unless `--verbose` or `--debug` is present, the script will silently
    (to allow for seamless integration with ifupdown or other network
    management tools) exit with status 0 on success and status 1 upon
    errors and failure.

    `--verbose` enables usage and status messages on stdout
    and error messages on stderr.

    `--debug` adds some information on the internal workings.
    Must be first argument if present.

  * __down__<br>
    Bring down all interfaces matching `wgp[a-z]{2}` restoring the default routing and DNS.

  * __up__<br>
    Bring up an wireguard interface named wgpcc (cc being the countrycode)
    and set the default routing via it.
    As only one wgp interface can be up at any time, it will firstly bring
    down any existing wgp[a-z]{2} interface.

  * __<ins>CC</ins>__<br>
    Two letter country code.

  * __rand__<br>
    Selects random conf for given country-code.
    (this is the default as well as fallback for ### and <CONFIGFILE>)

  * __<ins>INDEX</ins>__<br>
    Select config for given country-code with this "index"
    matching the regex [0-9a-z]+

  * __rtt__<br>
    Select config for peer with lowest latency (ping rtt).

  __<ins>CONFIGFILE</ins>__<br>
    hardcodes the config file to use

  * __dns__<br>
    Update /etc/resolv.conf with the DNS server from the config file.


## EXAMPLES

`proton-wg.sh up ch`<br>
    will randomly select a config file matching /etc/wireguard/wgpch[0-9a-z]+.conf

`proton-wg.sh up dk rtt dns`<br>
    will among config files matching /etc/wireguard/wgpdk[0-9a-z]+.conf
    select the one with lowest latency peer (ping rtt)
    and update /etc/resolv.conf with the DNS server from the config file

`proton-wg.sh up us 42`<br>
    will select a config file named /etc/wireguard/wgpus42.conf if present
    and otherwise randomly select one correctly named 'us' config file 

Example of how one can use this script together with ifupdown:

/etc/network/interfaces.d/wgproton
```
allow noauto wgpch
iface wgpch inet manual
      pre-up /bin/sh /path/to/proton-wg.sh up ch rtt dns
      down /bin/sh /path/to/proton-wg.sh down

allow noauto wgpus
iface wgpus inet manual
      pre-up /bin/sh /path/to/proton-wg.sh up us rtt dns
      down /bin/sh /path/to/proton-wg.sh down
```

## DEPENDENCIES

This script depends on being executed as root in a POSIX shell environment with the following utilities available:<br>
cat cut grep head id ip ls sed shuf wc wg

To ensure this in a Debian based distribution:<br>
```
sudo apt install dash coreutils sed iproute2 wireguard-tools
```

