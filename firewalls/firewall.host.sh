#!/bin/sh

#       host107
echo "starting flush"
#
# rc.flush-iptables - Resets iptables to default values.
#
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program or from the site that you downloaded it
# from; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307   USA

#
# Configurations
#

IPT4="$(which iptables)"
IPT6="$(which ip6tables)"
IPSET="$(which ipset)"

#
# reset the default policies in the filter table.
#

$IPT4 -P INPUT ACCEPT
$IPT4 -P FORWARD ACCEPT
$IPT4 -P OUTPUT ACCEPT

#
# reset the default policies in the nat table.
#

$IPT4 -t nat -P PREROUTING ACCEPT
$IPT4 -t nat -P POSTROUTING ACCEPT
$IPT4 -t nat -P OUTPUT ACCEPT

#
# reset the default policies in the mangle table.
#

$IPT4 -t mangle -P PREROUTING ACCEPT
$IPT4 -t mangle -P POSTROUTING ACCEPT
$IPT4 -t mangle -P INPUT ACCEPT
$IPT4 -t mangle -P OUTPUT ACCEPT
$IPT4 -t mangle -P FORWARD ACCEPT

#
# flush all the rules in the filter and nat tables.
#

$IPT4 -F
$IPT4 -t nat -F
$IPT4 -t mangle -F

#
# erase all chains that's not default in filter and nat table.
#

$IPT4 -X
$IPT4 -t nat -X
$IPT4 -t mangle -X

#
# очищаем таблицы ipset
#

#$IPSET flush

#---НАЧАЛО----------------------------------------------------------------------
#                               СКРИПТА
#-----------------------------------------------------------------------ЗДЕСЬ---

#!/bin/sh

echo "begin"
#
# rc.firewall - Initial SIMPLE IP Firewall script for Linux 2.4.x and iptables
#
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program or from the site that you downloaded it
# from; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307   USA
#

###########################################################################
###########################################################################
#
# 1. Configuration options.
#
echo "1. Configuration options."
#
# 1.1 Internet Configuration.
#
echo "1.1 Hoster Public Internet Configuration."
PUBLIC_IFACE="vmbr0"
PUBLIC_IP4_ADDR=""
PUBLIC_IP6_ADDR=""
PUBLIC_IP4_RANGE=""
PUBLIC_IP4_BROADCAST=""

#
# 1.1.1 DHCP
#

#
# 1.1.2 PPPoE
#

#
# 1.2 Local Area Network configuration.-----------------------------------------
#
# your LAN's IP range and localhost IP. /24 means to only use the first 24
# bits of the 32 bit IP address. the same as netmask 255.255.255.0
#
echo "1.2 Local Area Network configuration."
LAN_111_IFACE=""
LAN_111_IP4_ADDR=""
LAN_111_IP4_RANGE="192.168.111.0/24"
LAN_111_IP4_BROADCAST="192.168.111.255"

echo "1.2 Hoster Private Area Network configuration."
PRIVATE_IFACE="vmbr1"
PRIVATE_IP4_ADDR=""
PRIVATE_IP4_RANGE=""
PRIVATE_IP4_BROADCAST=""

echo "1.2 Host Internal LAN Network configuration."
LAN_PRI_IFACE="vmbr2"
LAN_PRI_IP4_ADDR="10.10.7.1"
LAN_PRI_IP4_RANGE="10.10.7.0/24"
LAN_PRI_IP4_BROADCAST="10.10.7.255"

LAN_SEC_IFACE=""
LAN_SEC_IP4_ADDR=""
LAN_SEC_IP4_RANGE=""
LAN_SEC_IP4_BROADCAST=""

#
# 1.3 DMZ Configuration.--------------------------------------------------------
#
echo "1.3 Host Internal DMZ Network Configuration."
#
# 1.4 Localhost Configuration.--------------------------------------------------
#
echo "1.4 Loopback Configuration."
LO_IFACE="lo"
LO_IP4_ADDR="127.0.0.1"
LO_IP4_RANGE="127.0.0.1/8"
LO_IP6_ADDR="::1/128"

#
# 1.5 IPTables Configuration.---------------------------------------------------
#
echo "1.5 IPTables Configuration."
IPT4="$(which iptables)"
IPT6="$(which ip6tables)"
IPSET="$(which ipset)"

#
# 1.6 Other Configuration.------------------------------------------------------
#
echo "1.6 Other Configuration."
PUBLIC_IP4_GATE102=""
PUBLIC_IP4_HOST102=""

###########################################################################
###########################################################################
#
# 2. Module loading.
#
echo "2. Module loading."
#
# Needed to initially load modules
#

/sbin/depmod -a

#
# 2.1 Required modules
#

/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_filter
/sbin/modprobe iptable_mangle
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_limit
/sbin/modprobe ipt_state
/sbin/modprobe ipt_REJECT

#
# 2.2 Non-Required modules
#

#/sbin/modprobe ipt_owner

#/sbin/modprobe ipt_MASQUERADE
#/sbin/modprobe ip_conntrack_ftp
#/sbin/modprobe ip_conntrack_irc
#/sbin/modprobe ip_nat_ftp
#/sbin/modprobe ip_nat_irc

###########################################################################
###########################################################################
#
# 3. /proc set up.
#
echo "3. /proc set up."
#
# 3.1 Required proc configuration
#

echo "1" > /proc/sys/net/ipv4/ip_forward

#
# 3.2 Non-Required proc configuration
#

#echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
#echo "1" > /proc/sys/net/ipv4/conf/all/proxy_arp
#echo "1" > /proc/sys/net/ipv4/ip_dynaddr

################################################################################
################################################################################
#
# 4. rules set up.
#
echo "4. rules set up."
######--------------------------------------------------------------------------
######--------------------------------------------------------------------------
# 4.1 Filter table
#
echo "4.1 Filter table"
#
# 4.1.1 Set policies------------------------------------------------------------
#

$IPT4 -P INPUT DROP
$IPT4 -P OUTPUT DROP
$IPT4 -P FORWARD DROP

#
# 4.1.2 Create userspecified chains---------------------------------------------
#

$IPT4 -N black_list

$IPSET create black_list hash:ip -exist
$IPSET create set_lan_local hash:net -exist
$IPSET create set_trust hash:ip -exist
$IPSET create set_proxmox hash:ip -exist

#
# Create chain for bad tcp packets----------------------------------------------
#

$IPT4 -N bad_tcp

#
# Create separate chains for ICMP, TCP and UDP to traverse----------------------
#

$IPT4 -N allowed
$IPT4 -N tcp_pts
$IPT4 -N udp_pts
$IPT4 -N icmp_pts

#
# 4.1.3 Create content in userspecified chains----------------------------------
#

$IPT4 -A black_list -p all -m set --match-set black_list src -d 0/0 -j DROP

$IPSET add set_lan_local $LAN_PRI_IP4_RANGE -exist

$IPSET add set_proxmox $PUBLIC_IP4_HOST102 -exist

$IPSET add set_trust $PUBLIC_IP4_OFFICE_MSK1 -exist


#
# bad_tcp chain-----------------------------------------------------------------
#

$IPT4 -A bad_tcp -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset
$IPT4 -A bad_tcp -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "New not syn: "
$IPT4 -A bad_tcp -p tcp ! --syn -m state --state NEW -j DROP

#
# allowed chain-----------------------------------------------------------------
#

$IPT4 -A allowed -p TCP --syn -j ACCEPT
$IPT4 -A allowed -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT4 -A allowed -p TCP -j DROP

#
# TCP rules---эти правила для недоверенных сетей ################################
#
echo "4.1.3 tcp_pts rules"
$IPT4 -A tcp_pts        -p TCP  -s 0/0						-d 0/0						--dport 6014			-j allowed      # SSH
$IPT4 -A tcp_pts        -p TCP  -s 0/0						-d 0/0						--dport 22			-j allowed      # SSH
$IPT4 -A tcp_pts        -p TCP  -s 0/0						-d 0/0						--dport 80			-j DROP         # http
$IPT4 -A tcp_pts        -p TCP  -m set --match-set set_trust src		-d 0/0						--dport 8006			-j allowed      # proxmox web
$IPT4 -A tcp_pts        -p TCP  -m set --match-set set_lan_local src		-d $LAN_PRI_IP4_ADDR				--dport 139			-j allowed      # NetBIOS Session Service
$IPT4 -A tcp_pts        -p TCP  -m set --match-set set_lan_local src		-d $LAN_PRI_IP4_ADDR				--dport 445			-j allowed      # NetBIOS Session Service
$IPT4 -A tcp_pts        -p TCP  -m set --match-set set_lan_local src		-d 0/0						--dport 10050			-j allowed      # zabbix

#
# UDP ports---эти правила для недоверенных сетей ################################
#
echo "4.1.3 udp_pts rules"
$IPT4 -A udp_pts        -p UDP  -m set --match-set set_proxmox src		-d 0/0						-m multiport --port 5404,5405	-j ACCEPT       # proxmox
# $IPT4 -A udp_pts      -p UDP  -s 0/0						-d 0/0						--dport 53			-j ACCEPT       # DNS
$IPT4 -A udp_pts        -p UDP  -m set --match-set set_lan_local src		-d 0/0						--dport 123			-j ACCEPT       # NTP
$IPT4 -A udp_pts        -p UDP  -m set --match-set set_lan_local src		-d $LAN_PRI_IP4_ADDR				--dport 137			-j ACCEPT       # NetBIOS Name Service
$IPT4 -A udp_pts        -p UDP  -m set --match-set set_lan_local src		-d $LAN_PRI_IP4_ADDR				--dport 138			-j ACCEPT       # NetBIOS Datagram Service
$IPT4 -A udp_pts        -p UDP  -s 0/0						-d 0/0						--dport 17500			-j DROP         #

#
# In Microsoft Networks you will be swamped by broadcasts. These lines
# will prevent them from showing up in the logs.
#

$IPT4 -A udp_pts        -p UDP  -s 0/0  -i $PUBLIC_IFACE			-d $PUBLIC_IP4_BROADCAST			--dport 135:139			-j DROP         #

#
# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
#

$IPT4 -A udp_pts        -p UDP  -s 0/0						-d 255.255.255.255				--dport 67:68			-j DROP         #

#
# ICMP rules ####################################################################
#

$IPT4 -A icmp_pts -p ICMP -s 0/0 --icmp-type 8 -j ACCEPT
$IPT4 -A icmp_pts -p ICMP -s 0/0 --icmp-type 11 -j ACCEPT

#################################################################################
# 4.1.4 INPUT chain---Траффик к ЛОКАЛЬНЫМ процессам #############################
#################################################################################
echo "4.1.4 INPUT chain"
#
# здесь правила для отладки ----------------------------------------------------
#

#$IPT4 -A INPUT -i $LAN_10_0_3_0_IFACE -j LOG --log-prefix "LAN_10_0_3_0 INPUT: "

#
# Bad TCP packets we don't want.------------------------------------------------
#

$IPT4 -A INPUT -p all -j black_list
$IPT4 -A INPUT -p tcp -j bad_tcp

#
# Rules for special networks not part of the Internet---------------------------
#
echo "4.1.4 Rules for special networks not part of the Internet"
$IPT4 -A INPUT -p ALL -i $LO_IFACE -s $LO_IP4_RANGE -j ACCEPT
$IPT4 -A INPUT -p ALL -i $LO_IFACE -s $LAN_PRI_IP4_ADDR -j ACCEPT
#$IPT4 -A INPUT -p ALL -i $LO_IFACE -s $PRIVATE_IP4_ADDR -j ACCEPT
$IPT4 -A INPUT -p ALL -i $LO_IFACE -s $PUBLIC_IP4_ADDR -j ACCEPT

#
# Special rule for DHCP requests from LAN, which are not caught properly
# otherwise. Это правило ДЛЯ ПРИЁМА ЗАПРОСОВ DHCP из ЛОКАЛКИ. ПРИ-Ё-МА.
#

#$IPT4 -A INPUT -p UDP -i $LAN_111_IFACE --dport 67 --sport 68 -j DROP

#
# Rules for incoming packets from the internet.---------------------------------
#

$IPT4 -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT

$IPT4 -A INPUT -p TCP -s 0/0 -d 0/0 -j tcp_pts
$IPT4 -A INPUT -p UDP -s 0/0 -d 0/0 -j udp_pts
$IPT4 -A INPUT -p ICMP -s 0/0 -d 0/0 -j icmp_pts

#
# If you have a Microsoft Network on the outside of your firewall, you may
# also get flooded by Multicasts. We drop them so we do not get flooded by
# logs
#

$IPT4 -A INPUT -i $PUBLIC_IFACE -d 224.0.0.0/8 -j DROP
$IPT4 -A INPUT -d 239.255.255.250 -j DROP

#
# Log weird packets that don't match the above.
#

$IPT4 -A INPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT INPUT died: "

#-------------------------------------------------------------------------------
# 4.1.5 FORWARD chain---Проходящий мимо траффик---------------------------------
#-------------------------------------------------------------------------------
echo "4.1.5 forward chain"
#
# Здесь правила для отладки ----------------------------------------------------
#

#$IPT4 -A FORWARD -o $LAN_10_2_5_0_IFACE -j LOG --log-prefix "LAN_10_2_5_0 FORWARD: "

#
# Форвард на виртуальных свитчах -----------------------------------------------
#

#$IPT4 -A FORWARD -d $LAN_PRI_IP4_RANGE -o $LAN_PRI_IFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#$IPT4 -A FORWARD -s $LAN_PRI_IP4_RANGE -i $LAN_PRI_IFACE -j ACCEPT
$IPT4 -A FORWARD -i $LAN_PRI_IFACE -o $LAN_PRI_IFACE -j ACCEPT
$IPT4 -A FORWARD -o $LAN_PRI_IFACE -j REJECT --reject-with icmp-port-unreachable
$IPT4 -A FORWARD -i $LAN_PRI_IFACE -j REJECT --reject-with icmp-port-unreachable

#$IPT4 -A FORWARD -d $PRIVATE_IP4_RANGE -o $PRIVATE_IFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#$IPT4 -A FORWARD -s $PRIVATE_IP4_RANGE -i $PRIVATE_IFACE -j ACCEPT
$IPT4 -A FORWARD -i $PRIVATE_IFACE -o $PRIVATE_IFACE -j ACCEPT
$IPT4 -A FORWARD -o $PRIVATE_IFACE -j REJECT --reject-with icmp-port-unreachable
$IPT4 -A FORWARD -i $PRIVATE_IFACE -j REJECT --reject-with icmp-port-unreachable

#$IPT4 -A FORWARD -d $PUBLIC_IP4_RANGE -o $PUBLIC_IFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#$IPT4 -A FORWARD -s $PUBLIC_IP4_RANGE -i $PUBLIC_IFACE -j ACCEPT
$IPT4 -A FORWARD -i $PUBLIC_IFACE -o $PUBLIC_IFACE -j ACCEPT
$IPT4 -A FORWARD -o $PUBLIC_IFACE -j REJECT --reject-with icmp-port-unreachable
$IPT4 -A FORWARD -i $PUBLIC_IFACE -j REJECT --reject-with icmp-port-unreachable

#
# Bad TCP packets we don't want-------------------------------------------------
#

$IPT4 -A FORWARD -p tcp -j bad_tcp

#
# Accept the packets we actually want to forward--------------------------------
#

$IPT4 -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

#
# Log weird packets that don't match the above.---------------------------------
#

$IPT4 -A FORWARD -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT FORWARD died: "

#-------------------------------------------------------------------------------
# 4.1.6 OUTPUT chain ---Траффик от ЛОКАЛЬНЫХ процессов--------------------------
#-------------------------------------------------------------------------------
echo "4.1.6 OUTPUT chain"
#
# Здесь правила для отладки ----------------------------------------------------
#

#$IPT4 -A OUTPUT

#
# Bad TCP packets we don't want.------------------------------------------------
#

$IPT4 -A OUTPUT -p tcp -j bad_tcp

#
# Special OUTPUT rules to decide which IP's to allow.---------------------------
#

$IPT4 -A OUTPUT -p ALL -s $LO_IP4_RANGE                 -j ACCEPT
$IPT4 -A OUTPUT -p ALL -s $LAN_PRI_IP4_ADDR             -j ACCEPT
#$IPT4 -A OUTPUT -p ALL -s $PRIVATE_IP4_ADDR            -j ACCEPT
$IPT4 -A OUTPUT -p ALL -s $PUBLIC_IP4_ADDR              -j ACCEPT

#
# Log weird packets that don't match the above.---------------------------------
#

$IPT4 -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT OUTPUT died: "

######--------------------------------------------------------------------------
######--------------------------------------------------------------------------
# 4.2 nat table
#
echo "4.2 nat table"
#
# 4.2.1 Set policies
#

#
# 4.2.2 Create user specified chains
#

#
# 4.2.3 Create content in user specified chains
#

#
# 4.2.4 PREROUTING chain--------------------------------------------------------
#

#
# 4.2.5 POSTROUTING chain-------------------------------------------------------
#

#
# Enable simple IP Forwarding and Network Address Translation-------------------
#

#
# 4.2.6 OUTPUT chain------------------------------------------------------------
#

######--------------------------------------------------------------------------
######--------------------------------------------------------------------------
# 4.3 mangle table
#
echo "4.3 mangle table"
#
# 4.3.1 Set policies
#

#
# 4.3.2 Create user specified chains
#

#
# 4.3.3 Create content in user specified chains
#

#
# 4.3.4 PREROUTING chain
#

#
# 4.3.5 INPUT chain
#

#
# 4.3.6 FORWARD chain
#

#
# 4.3.7 OUTPUT chain
#

#
# 4.3.8 POSTROUTING chain
#

echo "end"
#service fail2ban restart
#systemctl restart fail2ban.service
