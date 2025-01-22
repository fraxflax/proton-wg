#!/bin/sh
#
# proton-wg.sh - ProtonVPN Linux Client WireGuard interface setup script
#
# brings down/up an wireguard interface named wgproton
# and sets up the routing and dns via it 
# 
# proton-wg.sh must be run as root
#
# proton-wg.sh is free software written by Fredrik Ax <proton-wg@axnet.nu>
# Feel free to modify and/or (re)distribute it in any way you like.
# (It's always nice to be mentioned though ;-) )
#
# proton-wg.sh comes with ABSOLUTELY NO WARRANTY.
#
# If you expirence any problems with proton-wg.sh, are lacking any
# functionality or just want to voice your opions about it, feel free
# to contact me via e-mail: Fredrik Ax <proton-wg@axnet.nu>
# (also, if you need a script for setting up a Linux router to route 
#  certain subnets via ProtonVPN, feel free to contact me)
#

protonwg=${0##*/}
usage() {
    ERRMSG=''; [ "$1" ] && ERRMSG="

###
# ERROR:
# $1
###
"
    which "$PAGER" >/dev/null 2>&1 || {
	if which less >/dev/null 2>&1; then
	    PAGER=less
	elif which more >/dev/null 2>&1; then
	    PAGER=more
	else
	    PAGER=cat
	fi
    }
    $PAGER <<EOF
$ERRMSG

DESCRIPTION:

This script selects among config files that have been generated at
  https://account.proton.me/vpn/WireGuard
and downloaded to /etc/wireguard/ named: wgp[a-z]{2}[0-9a-z]+.conf
where [a-z]{2} is the two letter contrycode and [0-9a-z]+ is the "index"
using the selected config to bring up an wireguard Proton VPN.

OBSERVE that you need to edit the config files commenting out the
Address line and the DNS line:
  #Address = 10.2.0.2/32
  #DNS = 10.2.0.1
BUT do not remove the lines, they are expected to be in the file,
just commented out without whitespace after the #

Examples of of valid config filenames:
/etc/wireguard/wgpuk142.conf
/etc/wireguard/wgpch42tor.conf

USAGE:

  $protonwg [ --verbose | --debug ]  down | up ...

  $protonwg down

  $protonwg up <cc> [ rand | <###> | rtt | <CONFIGFILE> ] [ dns ]


OPTIONS:

  --verbose | --debug
    Unless --verbose and/or --debug is present, the script will silently
    (to allow for seamless integration with ifupdown or other network
    management tools) exit with status 0 on success and status 1 upon
    errors and failure.
    --verbose enables usage and status messages on stdout
    and error messages on stderr.
    --debug adds some information on the internal workings.
    Must be first argument if present.

  down
    Bring down all interfaces matching wgp[a-z]{2}
    restoring the default routing and DNS.

  up
    Bring up an wireguard interface named wgpcc (cc being the countrycode)
    and set the default routing via it.
    As only one wgp interface can be up at any time, it will firstly bring
    down any existing wgp[a-z]{2} interface.

  <cc>
    Two letter country code.

  rand
    Selects random conf for given country-code.
    (this is the default as well as fallback for ### and <CONFIGFILE>)

  <###>
    Select config for given country-code with this "index"
    matching the regex [0-9a-z]+

  rtt
    Select config for peer with lowest latency (ping rtt).

  <CONFIGFILE>
    hardcodes the config file to use

  dns
    Update /etc/resolv.conf with the DNS server from the config file.


EXAMPLES:

'$protonwg up ch'
    will randomly select a config file matching /etc/wireguard/wgpch[0-9a-z]+.conf

'$protonwg up dk rtt dns'
    will among config files matching /etc/wireguard/wgpdk[0-9a-z]+.conf
    select the one with lowest latency peer (ping rtt)
    and update /etc/resolv.conf with the DNS server from the config file

'$protonwg up us 42'
    will select a config file named /etc/wireguard/wgpus42.conf if present
    and otherwise randomly select one correctly named 'us' config file 

Example of how one can use this script together with ifupdown:

~~~ /etc/network/interfaces.d/wgproton ~~~

allow noauto wgpch
iface wgpch inet manual
      pre-up /bin/sh /path/to/$protonwg up ch rtt dns
      down /bin/sh /path/to/$protonwg down

allow noauto wgpus
iface wgpus inet manual
      pre-up /bin/sh /path/to/$protonwg up us rtt dns
      down /bin/sh /path/to/$protonwg down

DEPENDENCIES:

  This script depends on being executed as root in a POSIX compliant
  shell environment with the following utilities available:
    cat cut grep head id ip ls sed shuf wc wg

  To ensure this in a Debian based distribution:
    sudo apt install dash coreutils sed iproute2 wireguard-tools

$ERRMSG

EOF
    [ "$ERRMSG" ] && {
	[ "$PAGER" = cat ] || printf '%s' "$ERRMSG" >&2
    }
    exit 1
}

VERBOSE=''
[ "$1" = '--verbose' ] && { VERBOSE=y ; shift ; }
verbose() { [ "$VERBOSE" ] && printf '%s\n' "$*" >&2 ; }

DBG=''
[ "$1" = '--debug' ] && { DBG=y ; VERBOSE=y ; shift ; }
dbg() { [ "$DBG" ] && printf '%s\n' "$*" >&2 ; }

die() { verbose "$@" ; exit 1 ; }

# Let's put the "standard" paths first in PATH to ensure we get the standard utilities we need
# and remove duplicates in PATH before exporting it
NEWPATH='/sbin:/bin:/usr/sbin:/usr/bin'
OIFS=$IFS
IFS=:
for p in $PATH; do
    case ":$NEWPATH:" in
        *:"$p":*) ;;
        *) NEWPATH="$NEWPATH:$p" ;;
    esac
done
IFS=$OIFS
PATH=$NEWPATH
export PATH
for x in cat id head grep ip ls sed cut wc shuf wg; do
    which $x >/dev/null || usage "'$x' not found in PATH."
done

# ensure root
[ $(id -u) -eq 0 ] || usage 'This script must be run as root!'


down() {
    [ -f /etc/resolv.conf.wgprotonbakup ] && {
	head -1 /etc/resolv.conf | grep -qE '^# proton-wg.sh dns$' && {
	    cat /etc/resolv.conf.wgprotonbakup > /etc/resolv.conf
	}
	rm /etc/resolv.conf.wgprotonbakup
    }
    for ifc in $(ip link show | grep -oE '^[0-9]+: wgp[a-z]{2}:' | grep -oE 'wgp[a-z]{2}'); do
	ip link del dev $ifc
    done
}
defaultroute() {
    ip route show table main | grep -E '^default' | grep -oE 'via .*' | while read DEFAULTROUTE; do
	eval "ip route add table main $1/32 $DEFAULTROUTE" 2>/dev/null
    done
    ip route show table default | grep -E '^default' | grep -oE 'via .*' | while read DEFAULTROUTE; do
	eval "ip route add table default $1/32 $DEFAULTROUTE" 2>/dev/null
    done
}

case $1 in
    up)	: ;;
    down)
	down
	[ $VERBOSE ] && {
	    printf '\n--- dns ---\n'
	    cat /etc/resolv.conf
	}
	exit 0
	;;
    *) usage ;;
esac

# two letter country code?
printf '%s' "$2" | grep -qE '^[a-z]{2}$' || usage 'Invalid country-code'
CC=$2
IFACE=wgp$CC
dbg IFACE=$IFACE

[ -d /etc/wireguard ] || die "No /etc/wireguard directory found"

# ensure we have default route(s) in the main table and/or default table
( ip route show table main; ip route show table default ) | grep -qE '^default' || \
    die "No default route in table main nor in table default"

# Select configuration to use
DNS=''
if [ "$3" = 'dns' ]; then
    DNS=y
    shift
elif [ "$4" = 'dns' ]; then
    DNS=y
fi

CONF=''
PEER=''
case $3 in
    rand|'') : ;;	# select random conf below

    rtt) # select conf by lowest latency
	RTT=999999
	
	for C in $(ls -1 /etc/wireguard/ | grep -E "^wgp$CC[0-9a-z]+.conf$"); do
	    P=$(grep -E '^Endpoint = ' "/etc/wireguard/$C" | \
		    grep -oE '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
	    [ "$P" ] || continue
	    # ensure peer is available via default route
	    defaultroute $P
	    R=$(ping -q -c3 -W1 $P | grep -E '^rtt' | sed -E 's/.* = [0-9.]+\/([0-9.]+).*/\1/')
	    printf '%s' "$R" | grep -qE '^[0-9.]+$' || continue
	    RI=${R%.*} 
	    RD=${R#*.}
	    RD=$(printf '%03d' "$RD" | cut -c1-3)
	    #dbg $R = $RI.$RD
	    R=$((RI*1000+RD)) #; dbg R=$R
	    dbg "$P RTT $R < $RTT ???" 
	    [ $R -lt $RTT ] && {
		RTT=$R
		CONF=/etc/wireguard/$C
		PEER=$P
	    }
	done
	dbg rttCONF=$CONF
	dbg rttPEER=$PEER
	;;

	*) # select conf by index or filename
	    if [ -f "/etc/wireguard/wgp$CC$3.conf" ]; then
		CONF="/etc/wireguard/wgp$CC$3.conf"
		dbg idxCONF=$CONF
	    else
		CONF="$3"
		[ -f "/etc/wireguard/$CONF" ] && CONF="/etc/wireguard/$CONF"
		dbg fileCONF=$CONF
	    fi
	    ;;
esac

[ -f "$CONF" ] || {
    cnt=$(ls -1 /etc/wireguard/ | grep -E "^wgp$CC[0-9a-z]+.conf$" | wc -l)
    dbg number of files: $cnt
    [ $cnt -gt 0 ] || die 'No configuration files found'
    cnt=$(shuf -i1-$cnt -n1)
    dbg randomly selected: $cnt
    i=1
    for CONF in $(ls -1 /etc/wireguard/wgp$CC*.conf | grep -E 'wgp[a-z]{2}[0-9a-z]+.conf$'); do
	[ $i -eq $cnt ] && break
	i=$((i+1))
    done
}
dbg CONF=$CONF
[ -f "$CONF" ] || die "No configuration file found"

[ "$PEER" ] || \
    PEER=$(grep -E '^Endpoint = ' $CONF | \
	       grep -oE '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
dbg PEER=$PEER
[ "$PEER" ] || die "No peer found in '$CONF'"

ADDR=$(grep -E '^#Address = ' $CONF | \
       grep -oE '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
dbg ADDR=$ADDR
[ "$ADDR" ] || die "No '#Address = <IPADDRESS>' found in '$CONF'"

GW=$(printf '%s' "$ADDR" | sed -E 's/(.*\.).*/\1/')1
dbg GW=$GW

# ensure peer is available via default route
defaultroute $PEER
ping -q -c1 -w3 $PEER >/dev/null || die "Peer $PEER not reachable"

down
ip link add dev $IFACE type wireguard || die  "Failed to add interface"
ip address add $ADDR peer $GW dev $IFACE || die "Failed to set address"
wg setconf $IFACE $CONF || die "Failed to set wireguard configuration"
ip link set up dev $IFACE || die "Failed to bring up interface"
ip route add table main 0.0.0.0/1 via $GW dev $IFACE src $ADDR
ip route add table main 128.0.0.0/1 via $GW dev $IFACE src $ADDR
#ip route add table default 0.0.0.0/1 via $GW dev $IFACE src $ADDR
#ip route add table default 128.0.0.0/1 via $GW dev $IFACE src $ADDR

[ $VERBOSE ] && {
    printf '\n--- interface ---\n'
    ip addr show dev $IFACE
    printf '\n--- wireguard ---\n'
    wg show $IFACE
    printf '\n--- routing ---\n# main table:\n'
    ip route show table main
    [ $(ip route show table default 2>/dev/null | wc -l) -gt 0 ] && {
	printf '# default table:\n'
	ip route show table default
    }
}
	cat /etc/resolv.conf > /etc/resolv.conf.wgprotonbakup
[ "$DNS" ] && { 
    ( printf '# proton-wg.sh dns\nnameserver %s\n' $GW ; sed -E 's/^\s*nameserver /#nameserver /g' /etc/resolv.conf.wgprotonbakup ) > /etc/resolv.conf
    [ $VERBOSE ] && {
	printf '\n--- dns ---\n'
	cat /etc/resolv.conf
    }
}

exit 0
