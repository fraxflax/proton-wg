#!/bin/sh
#
# proton-wg-router.sh - Wireguard router script for ProtonVPN
#
# proton-wg-router.sh utilized iproute2 ('ip route' and 'ip rule') and
# wireguard-tools to setup routing via ProtonVPN Wireguard interfaces
# for certain sources and destination.
#
# TODO:
# extend this script to give the option to force source addresses to
# use ProtonVPN DNS servers (e.g. by using iptables to redirect DNS)
#

# INTERFACE NAME
# The name of the Wireguard interface to be used for ProtonVPN
IFACE=wgproton

# The below *via* variables are space separated lists of source or
# destination CIDRs determining which traffic should be routerd via
# Proton and which should be routed via the default route

# Thew router itself vill not default route via Proton, but these
# destinations are always routed to via Proton (also from the router itself)
# unless listed in DSTviaDEFAULT also.
DSTviaPROTON=''

# These destinations are always routed via the default route, also
# from SRCviaPROTON listed CIDRs
# and has precedence over DSTviaPROTON if intersecting
DSTviaDEFAULT='10.0.0.0/8 172.16.0.0/14 192.168.0.0/16'

# These sources are routed via Proton by default unless they are also
# listed in SRCviaDEFAULT
# sources not listed here are default routed via the default route
SRCviaPROTON='10.46.254.0/24'

# These sources are by explicitly default routed via the default route
# and has precedence over SRCviaPROTON if intersecting
SRCviaDEFAULT='10.46.254.212/30'

##############################################################################
# Do not change variables below this point
# unless you really know what you are doing :-)

# prios for linux default 'from all lookup main' rule,
# and 'from all lookup default' rule
# this script will insert them unless they already exists
_all2defaultprio=32767 
_all2mainprio=32766 

# These are the prios overriding the normal routing for the different sources
_viaPROTONprio=$((_all2mainprio-1))
_viaDEFAULTdefaultprio=$((_viaPROTONprio-1))
_viaDEFAULTmainprio=$((_viaDEFAULTdefaultprio-1))

SILENT=
[ "$1" = '--silent' ] && { SILENT=y ; shift ; }
verbose() { [ "$VERBOSE" ] && printf '%s\n' "$*" >&2 ; }
DBG=
[ "$1" = '--debug' ] && { DBG=y ; SILENT='' ; shift ; }

dbg() { [ "$DBG" ] && printf '%s\n' "$*" >&2 ; }
inf() { [ $SILENT ] || printf '%s\n' "$*" ; }
die() { printf '%s\n' "$*" >&2 ; exit 1 ; }

defaultroute() {
    ip route show table main 2>/dev/null | grep -E '^default' | grep -oE 'via .*' | while read DEFAULTROUTE; do
	eval "ip route add table main $1 $DEFAULTROUTE" 2>/dev/null
    done
    ip route show table default 2>/dev/null | grep -E '^default' | grep -oE 'via .*' | while read DEFAULTROUTE; do
	eval "ip route add table default $1 $DEFAULTROUTE" 2>/dev/null
    done
}
dbg _viaDEFAULTmainprio=$_viaDEFAULTmainprio
dbg _viaDEFAULTdefaultprio=$_viaDEFAULTdefaultprio
dbg _viaPROTONprio=$_viaPROTONprio
dbg _all2mainprio=$_all2mainprio
dbg _all2defaultprio=$_all2defaultprio

##############################################################################
# Check that things are as we expect them to be
[ $(id -u) -eq 0 ] || die 'This script must be run as root!'
[ -d /etc/wireguard ] || die "No /etc/wireguard directory found"
for prio in $(ip rule show | grep -E '[0-9]+:\s+from all lookup main$' | cut -d: -f1); do
    [ $prio -eq $_all2mainprio ] || die "unexpected all2mainprio $prio (=/= $_all2mainprio) ... aborting!"
done
[ $prio ] || die 'no all2main rule found ... aborting!' #ip rule add prio $_all2mainprio from all lookup main
for prio in $(ip rule show | grep -E '[0-9]+:\s+from all lookup default$' | cut -d: -f1); do
    [ $prio -eq $_all2defaultprio ] || die "unexpected all2defaultprio $prio (=/= $_all2defaultprio) ... aborting!"
done
[ $prio ] || die 'no all2default rule found ... aborting!' #ip rule add prio $_all2defaultprio from all lookup default
( ip route show table main; ip route show table default ) 2>/dev/null | grep -qE '^default' || \
    die 'No default route in table main nor in table default ... aborting!'

##############################################################################
# commands
down() {
    ip route del default via $GW dev $IFACE table $_viaPROTONprio 2>/dev/null 
    for cidr in $SRCviaPROTON; do
	ip rule del from $cidr lookup $_viaPROTONprio prio $_viaPROTONprio 2>/dev/null
    done
    for cidr in $DSTviaPROTON; do
	ip rule del to $cidr lookup $_viaPROTONprio prio $_viaPROTONprio 2>/dev/null
    done
    for cidr in $DSTviaDEFAULT; do
	ip rule del to $cidr lookup main prio $_viaDEFAULTmainprio 2>/dev/null
	ip rule del to $cidr lookup default prio $_viaDEFAULTdefaultprio 2>/dev/null
    done
    for cidr in $SRCviaDEFAULT; do
	ip rule del from $cidr lookup main prio $_viaDEFAULTmainprio 2>/dev/null
	ip rule del from $cidr lookup default prio $_viaDEFAULTdefaultprio 2>/dev/null
    done
    ip link del dev $IFACE 2>/dev/null
    ip link add dev $IFACE type wireguard
    ip link set down dev $IFACE
}
case $1 in
    up)	: ;;
    down)
	down
	# cleanup
	#...
	exit 0
	;;
    *) die usage 'Invalid command (up/down)' ;;
esac

# two letter country code?
printf '%s' "$2" | grep -qE '^[a-z]{2}$' || die usage 'Invalid country-code'
CC=$2


CONF=
PEER=
case $3 in
    rand|'') : ;; # select random conf below

    rtt) # select conf by lowest latency
	RTT=999999
	for C in $(ls -1 /etc/wireguard/ | grep -E "^wgp$CC[0-9a-z]+.conf$"); do
	    P=$(grep -E '^Endpoint = ' "/etc/wireguard/$C" | grep -oE '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
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



##############################################################################

# ensure peer is available via default route
defaultroute $PEER
ping -q -c1 -w3 $PEER >/dev/null || die "Peer $PEER not reachable"

down

ip address add $ADDR peer $GW dev $IFACE || exit 1
wg setconf $IFACE $CONF || exit 1
ip link set up dev $IFACE || exit 1

for cidr in $DSTviaDEFAULT; do
    ip rule add to $cidr lookup main prio $_viaDEFAULTmainprio 2>/dev/null
    ip rule add to $cidr lookup default prio $_viaDEFAULTdefaultprio 2>/dev/null
done
for cidr in $SRCviaDEFAULT; do
    ip rule add from $cidr lookup main prio $_viaDEFAULTmainprio 2>/dev/null
    ip rule add from $cidr lookup default prio $_viaDEFAULTdefaultprio 2>/dev/null
done
for cidr in $SRCviaPROTON; do
    ip rule add from $cidr lookup $_viaPROTONprio prio $_viaPROTONprio 2>/dev/null
done
for cidr in $DSTviaPROTON; do
    ip rule add to $cidr lookup $_viaPROTONprio prio $_viaPROTONprio 2>/dev/null
done
ip route add default via $GW dev $IFACE table $_viaPROTONprio 2>/dev/null 

[ $SILENT ] || {
    printf '\n### Routing ###\n# Rules:\n'
    ip rule | grep -E "^($_all2mainprio|$_all2defaultprio|$_viaDEFAULTmainprio|$_viaDEFAULTdefaultprio|$_viaPROTONprio):" #| sort -n
    for t in $_viaPROTONprio main default; do
	printf '\n# Table %s:\n' $t
	[ $(ip route show table $t 2>/dev/null | wc -l) -gt 0 ] && { # don't show empty table error
	    ip route show table $t
	}
    done
    printf '###\n'
}
exit 0
