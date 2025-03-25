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

##############################################################################
### These variables needs to be correctly set to match your environment
###

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
DSTviaDEFAULT='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'

# These sources are routed via Proton by default unless they are also
# listed in SRCviaDEFAULT
# sources not listed here are default routed via the default route
SRCviaPROTON='10.46.254.0/24'

# These sources are by explicitly default routed via the default route
# and has precedence over SRCviaPROTON if intersecting
#SRCviaDEFAULT='10.46.254.213'
SRCviaDEFAULT='10.46.254.212/30'

##############################################################################
### This needs to be configured only if you intend to use the
### --named option (to set Proton as dns forwarder)
### 
# This is a bit clonky but it works fine for me
# 
# ( ... one day I might make it more intelligent actually figuring the
# existing (potentiall multi-line) forwarder statement from existing
# bind config and comment it out whilst adding the new one restoring
# it upong 'down' or if we cannot resolve via the GW ... )
#
# What '--named up' does is to replace the existing forwarders
# statement (MUST be on a single line) statements in $NAMEDCONF
# adding the proton DNS as the only forwarder
#
# upon down it will replace the existing forwarders statement with
# $NAMEDFORWARDERS

# File to replace forwarders statement in when using --named
NAMEDCONF='/etc/bind/named.conf.options'

# If you do not use a forwarders statement at all in your $NAMEDCONF
# set this variable to exactly this (you can leave the next line as is)
# and just comment out the NAMEDFORWARDERS line below).
NAMEDFORWARDERS='//forwarders { };'
# OBSERVE you also need to make sure it's in the options section of the
# $NAMEDCONF file: e.g. like this
# options {
#         //forwarders { };
# ...
# and that there are no more forwarders statements, not even commented out,
# in the $NAMEDCONF file.

# If you use a forwarders statement define it on a single line here:
NAMEDFORWARDERS='forwarders { 1.1.1.1; 1.0.0.1; 8.8.8.8; 8.8.4.4; };'
# and also make sure there is a single line forwarders statement in
# the $NAMEDCONF file

##############################################################################
### Do not change variables (or anything else) below this point,
### unless you really know what you are doing ;-)

# Interface prefix name of interface to be used will depend on the
# country code. So with the default of IFACE=wgp the interface will be
# named wgpse, wgpus, wgpde, etc depending on the country code.
IFACE=wgp

# prios for linux default 'from all lookup main' rule,
# and 'from all lookup default' rule
# this script will insert them unless they already exists
_all2defaultprio=32767 
_all2mainprio=32766 

# These are the prios overriding the normal routing for the different sources
_viaPROTONprio=$((_all2mainprio-1))
_viaDEFAULTdefaultprio=$((_viaPROTONprio-1))
_viaDEFAULTmainprio=$((_viaDEFAULTdefaultprio-1))

die() { printf '%s\n' "$*" >&2 ; exit 1 ; }
SILENT=''; [ "$1" = '--silent' ] && { SILENT=y ; shift ; }
wrn() { [ "$SILENT" ] || printf '%s\n' "$*" >&2 ; }
DBG='' ; [ "$1" = '--debug' ] && { DBG=y ; SILENT='' ; shift ; }
dbg() { [ "$DBG" ] && printf '%s\n' "$*" >&2 ; }
RESOLV=''; [ "$1" = '--dns' ] && { RESOLV='/etc/resolv.conf' ; shift ; }
BIND='';   [ "$1" = '--named' ] && { BIND=y ; shift ; }
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
dbg RESOLV=$RESOLV
dbg BIND=$BIND
dbg NAMEDCONF=$NAMEDCONF

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

info() {
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
##############################################################################
# commands
down() {
    if [ "$CC" ]; then
	IFACES="$IFACE$CC"
    else
	IFACES=$(ip link | grep -oE "^[0-9]+:\s+${IFACE}[a-z]{2}:\s" | grep -oE "${IFACE}[a-z]{2}")
    fi
    for ifc in $IFACES; do
	ip route del default via $GW dev $ifc table $_viaPROTONprio 2>/dev/null
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
	ip link del dev $ifc 2>/dev/null
	ip link add dev $ifc type wireguard
	ip link set down dev $ifc
    done
    # Always restore bind forwarders config it exists
    [ -w "$NAMEDCONF" ] \
	&& [ 1 -eq $(grep -cE "^\\s*(//\\s*)?forwarders\\s*\\{.*\\};\\s*$" "$NAMEDCONF") ] \
	&& perl -pi -e "s|(^\\s*)(//\\s*)?forwarders\\s*\\{.*\\};\\s*$|\$1$NAMEDFORWARDERS\\n|" "$NAMEDCONF" \
	&& which rndc >/dev/null && { rndc flush 2>/dev/null ; rndc reload >/dev/null 2>&1 ;}
}
# two letter country code?
if printf '%s' "$2" | grep -qE '^[a-z]{2}$'; then
    CC=$2
else
    [ "$1" = down ] || die 'Invalid country-code'
    CC=''
fi

case $1 in
    up)	: ;;
    down)
	down
	[ $SILENT ] || info
	exit 0
	;;
    *) die 'Invalid command (not up/down)' ;;
esac

[ "$BIND" ] && {
    [ -w "$NAMEDCONF" ] || die "--named file '$NAMEDCONF' not found or not writable ... aborting!"
    [ 1 -eq $(grep -cE "^\\s*(//\\s*)?forwarders\\s*\\{.*\\};\\s*$" "$NAMEDCONF") ] \
	|| die "must have exactly one a single line 'forwarders' statement in '$NAMEDCONF' ... aborting!"
    rndc status > /dev/null 2>&1 || die "rndc not available in PATH or 'rndc status' failed ... aborting!"
}

CONF=
PEER=
case $3 in
    rand|'') : ;; # select random conf below

    rtt) # select conf by lowest latency
	RTT=999999
	for C in $(ls -1 /etc/wireguard/ | grep -E "^wgp$CC[0-9a-z]+.conf$"); do
	    P=$(grep -E '^Endpoint = ' "/etc/wireguard/$C" | grep -oE '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
	    [ "$P" ] || continue
	    [ "$SILENT" ] || printf 'RTT %s %s: ' "$C" "$P"
	    # ensure peer is available via default route
	    defaultroute $P
	    R=$(ping -q -c3 -W1 $P | grep -E '^rtt' | sed -E 's/.* = [0-9.]+\/([0-9.]+).*/\1/')
	    printf '%s' "$R" | grep -qE '^[0-9.]+$' || { [ "$SILENT" ] || printf 'no reply'; continue; }
	    [ "$SILENT" ] || printf '%s ms\n' "$R"
	    RI=${R%.*} 
	    RD=${R#*.}; RD=${RD##*0}; [ "$RD" ] || RD=0
	    R=$((RI*1000+RD))
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

IFACE="$IFACE$CC"
ip link show dev $IFACE >/dev/null 2>&1 || ip link add dev $IFACE type wireguard
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

[ "$BIND" ] && {
    #perl -pi -e "s/^(\\s*forwarders\s*{)\\s*\$/\$1 $GW;\n/" "$NAMEDCONF"
    perl -pi -e "s|^(\\s*(//\\s*)?forwarders\\s*\\{).*\\};\\s*$|\$1 $GW; };\n|" "$NAMEDCONF" \
    rndc flush 2>/dev/null 
    rndc reload 2>/dev/null || wrn "WARNING: 'rndc reload' failed."
}

[ $SILENT ] || { info ; ping -q -c1 -w1 $GW >/dev/null ; wg show $IFACE ; }
exit 0
