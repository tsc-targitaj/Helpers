#!/bin/sh

# Скрипт файрволла для http(s)
# Машина 
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
echo "1.1 Internet Configuration."
PUBLIC_IFACE="eth0"
PUBLIC_IP4_ADDR=""
PUBLIC_IP4_RANGE="/23"
PUBLIC_IP4_BROADCAST=""
PUBLIC_IP6_ADDR=""

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
echo "1.2 Host Internal LAN Network configuration."
LAN_PRI_IFACE=""
LAN_PRI_IP4_ADDR=""
LAN_PRI_IP4_RANGE=""
LAN_PRI_IP4_BROADCAST=""

LAN_SEC_IFACE=""
LAN_SEC_IP4_ADDR=""
LAN_SEC_IP4_RANGE=""
LAN_SEC_IP4_BROADCAST=""

echo "1.2 Host Internal VPN  Network configuration."
PPTP_IFACE=""
PPTP_IP4_ADDR=""
PPTP_IP4_RANGE=""
PPTP_IP4_BROADCAST=""

OVPN_IFACE=""
OVPN_IP4_ADDR=""
OVPN_IP4_RANGE=""
OVPN_IP4_BROADCAST=""

echo "1.2 Local Area Network configuration."
LAN_11_IP4_RANGE="192.168.11.0/24"
LAN_13_IP4_RANGE="192.168.13.0/24"
LAN_15_IP4_RANGE="192.168.15.0/24"
LAN_00_IP4_RANGE="10.0.0.0/24"
LAN_31_IP4_RANGE="10.3.1.0/24"
LAN_32_IP4_RANGE="10.3.2.0/24"
LAN_33_IP4_RANGE="10.3.3.0/24"
LAN_41_IP4_RANGE="10.4.1.0/24"
LAN_51_IP4_RANGE="10.5.1.0/24"
LAN_52_IP4_RANGE="10.5.2.0/24"
LAN_55_IP4_RANGE="10.5.5.0/24"
LAN_56_IP4_RANGE="10.5.6.0/24"
LAN_71_IP4_RANGE="10.7.1.0/24"
LAN_81_IP4_RANGE="10.8.1.0/24"
LAN_82_IP4_RANGE="10.8.2.0/24"
LAN_91_IP4_RANGE="10.9.1.0/24"
LAN_105_IP4_RANGE="10.10.5.0/24"
LAN_106_IP4_RANGE="10.10.6.0/24"
LAN_107_IP4_RANGE="10.10.7.0/24"

#
# 1.3 DMZ Configuration.--------------------------------------------------------
#
echo "1.3 DMZ Configuration."
#
# 1.4 Localhost Configuration.--------------------------------------------------
#

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

#локальные машины блока сервисов ядра торговой системы

LAN_PRI_IP4_NET_CORE=""
LAN_PRI_IP4_NET_GATE=""
LAN_PRI_IP4_AFT_TRADE=""

#локальные машины блока прочих сервисов торговой системы

LAN_IP4_RMADM31="10.3.1.101"

#публичные машины торговой системы

PUBLIC_IP4_MT4_REAL31=""

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

#echo "1" > /proc/sys/net/ipv4/ip_forward

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
echo "4.1.1 Set policies"
$IPT4 -P INPUT DROP
$IPT4 -P OUTPUT DROP
$IPT4 -P FORWARD DROP

#
# 4.1.2 Create userspecified chains---------------------------------------------
#
echo "4.1.2 Create userspecified chains"
$IPT4 -N black_list

$IPSET create set_trust hash:ip -exist
$IPSET create black_list hash:ip -exist
#$IPSET create set_lan_all hash:net -exist
#$IPSET create set_lan_local hash:net -exist
#$IPSET create set_lan_remote hash:net -exist
#$IPSET create set_psql hash:ip -exist
#$IPSET create set_mysql hash:ip -exist
#$IPSET create set_ipsec hash:ip -exist
#$IPSET create set_front hash:ip -exist
#$IPSET create set_amq hash:ip -exist
#$IPSET create set_report hash:ip -exist
#$IPSET create set_front hash:ip -exist
#$IPSET create set_zabbix hash:ip -exist
#$IPSET create set_bareos hash:ip -exist
#$IPSET create set_elastic hash:ip -exist

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
echo "4.1.3 Create content in userspecified chains"
$IPT4 -A black_list -p all -m set --match-set black_list src -d 0/0 -j DROP

#$IPSET add set_lan_all $LAN_11_IP4_RANGE -exist
#$IPSET add set_lan_all $LAN_13_IP4_RANGE -exist
#$IPSET add set_lan_all $LAN_15_IP4_RANGE -exist
#$IPSET add set_lan_all $LAN_00_IP4_RANGE -exist
#$IPSET add set_lan_all $PPTP_IP4_RANGE -exist
#$IPSET add set_lan_all $OVPN_IP4_RANGE -exist

#$IPSET add set_lan_local $LAN_11_IP4_RANGE -exist
#$IPSET add set_lan_local $LAN_13_IP4_RANGE -exist
#$IPSET add set_lan_local $LAN_15_IP4_RANGE -exist
#$IPSET add set_lan_local $LAN_00_IP4_RANGE -exist
#$IPSET add set_lan_local $PPTP_IP4_RANGE -exist
#$IPSET add set_lan_local $OVPN_IP4_RANGE -exist

#$IPSET add set_lan_remote $LAN_11_IP4_RANGE -exist
#$IPSET add set_lan_remote $LAN_13_IP4_RANGE -exist
#$IPSET add set_lan_remote $LAN_15_IP4_RANGE -exist
#$IPSET add set_lan_remote $LAN_00_IP4_RANGE -exist
#$IPSET add set_lan_remote $PPTP_IP4_RANGE -exist
#$IPSET add set_lan_remote $OVPN_IP4_RANGE -exist

#$IPSET add set_psql $PUBLIC_IP4_GATE31 -exist

#$IPSET add set_mysql $PUBLIC_IP4_GATE31 -exist

#$IPSET add set_trust $PUBLIC_IP4_GATE31 -exist

#$IPSET add set_ipsec $PUBLIC_IP4_GATE31 -exist

#$IPSET add set_front $PUBLIC_IP4_WEB004 -exist
#$IPSET add set_front $PUBLIC_IP4_WEB005 -exist

#$IPSET add set_amq $PUBLIC_IP4_CRM31 -exist

#$IPSET add set_elastic $PUBLIC_IP4_WEB004 -exist
#$IPSET add set_elastic $PUBLIC_IP4_WEB005 -exist

#$IPSET add set_zabbix $PUBLIC_IP4_WEB004 -exist
#$IPSET add set_zabbix $PUBLIC_IP4_WEB005 -exist

#
# bad_tcp chain-----------------------------------------------------------------
#

$IPT4 -A bad_tcp -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset
$IPT4 -A bad_tcp -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "New not syn: "
$IPT4 -A bad_tcp -p tcp ! --syn -m state --state NEW -j DROP

#
# allowed chain-----------------------------------------------------------------
#

$IPT4 -A allowed -p tcp --syn -j ACCEPT
$IPT4 -A allowed -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT4 -A allowed -p tcp -j DROP

#
# TCP rules---эти правила для недоверенных сетей.-------------------------------
#
echo "4.1.3 TCP rules"
$IPT4 -A tcp_pts	-p tcp	-s 0/0						-d 0/0						--dport 6014			-j allowed	# SSH
$IPT4 -A tcp_pts	-p tcp	-s 0/0						-d 0/0						--dport 22			-j allowed	# SSH
#$IPT4 -A tcp_pts	-p tcp	-s 0/0						-d 0/0						--dport 53			-j allowed	# DNS
$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_trust src		-d 0/0						--dport 80			-j allowed	# http
#$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_front src		-d 0/0						--dport 80			-j allowed	# http
#$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_lan_all src		-d 0/0						--dport 80			-j allowed	# http
$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_trust src		-d 0/0						--dport 443			-j allowed	# https
#$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_front src		-d 0/0						--dport 443			-j allowed	# https
#$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_lan_all src		-d 0/0						--dport 443			-j allowed	# https
#$IPT4 -A tcp_pts	-p tcp	-m set --match-set set_ipsec src		-d 0/0						--dport 1701			-j ACCEPT	# L2TP
#$IPT4 -A tcp_pts	-p tcp	-s 0/0						-d 0/0						--dport 1194			-j allowed	# OVPN TCP
#$IPT4 -A tcp_pts	-p tcp	-s $LAN_IP4_ZABBIX102				-d 0/0						--dport 10050			-j allowed	# zabbix

#
# UDP ports---эти правила для недоверенных сетей--------------------------------
#
echo "4.1.3 UDP ports"
#$IPT4 -A udp_pts	-p udp	-s 0/0						-d 0/0						--dport 53			-j ACCEPT	# DNS
#$IPT4 -A udp_pts	-p udp	-m set --match-set set_lan_local src		-d 0/0						--dport 123			-j ACCEPT	# NTP
#$IPT4 -A udp_pts	-p udp	-m set --match-set set_ipsec src		-d 0/0						--dport 500			-j ACCEPT	# ipsec
#$IPT4 -A udp_pts	-p udp	-s 0/0						-d 0/0						--dport 1194			-j ACCEPT	# OVPN
#$IPT4 -A udp_pts	-p udp	-m set --match-set set_ipsec src		-d 0/0						--dport 1701			-j ACCEPT	# L2TP
$IPT4 -A udp_pts	-p udp	-s 0/0						-d 0/0						--dport 17500			-j DROP		#

#
# In Microsoft Networks you will be swamped by broadcasts. These lines
# will prevent them from showing up in the logs.
#

# $IPT4 -A udp_pts	-p udp	-s 0/0 -i $PUBLIC_IFACE				-d $PUBLIC_IP4_BROADCAST			--dport 135:139			-j DROP		# SMB flood
$IPT4 -A udp_pts	-p udp	-s 0/0						-d 0/0						--dport 135:139			-j DROP		# SMB flood

#
# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
#

$IPT4 -A udp_pts	-p udp	-s 0/0						-d 255.255.255.255				--dport 67:68			-j DROP		# DHCP flood

#
# ICMP rules--------------------------------------------------------------------
#
echo "4.1.3 ICMP rules"
$IPT4 -A icmp_pts -p icmp -s 0/0 --icmp-type 8 -j ACCEPT
$IPT4 -A icmp_pts -p icmp -s 0/0 --icmp-type 11 -j ACCEPT

#-------------------------------------------------------------------------------
# 4.1.4 INPUT chain---Траффик к ЛОКАЛЬНЫМ процессам-----------------------------
#-------------------------------------------------------------------------------
echo "4.1.4 INPUT chain"
#
# здесь правила для отладки ----------------------------------------------------
#

#$IPT4 -A INPUT -i $LAN_10_0_3_0_IFACE -j LOG --log-prefix "LAN_10_0_3_0 INPUT: "

#
# Bad TCP packets we don't want.------------------------------------------------
#
echo "4.1.4 Bad TCP packets we don't want."
$IPT4 -A INPUT -p all -j black_list
$IPT4 -A INPUT -p tcp -j bad_tcp

#
###
#

$IPT4 -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT

#
# Rules for special networks not part of the Internet---------------------------
#
echo "4.1.4 Rules for special networks not part of the Internet"
$IPT4 -A INPUT -p all -i $LO_IFACE -s $LO_IP4_RANGE -d 0/0 -j ACCEPT
#$IPT4 -A INPU -p all -i $LO_IFACE -s $LAN_PRI_IP4_ADDR -d 0/0 -j ACCEPT
$IPT4 -A INPUT -p all -i $LO_IFACE -s $PUBLIC_IP4_ADDR -d 0/0 -j ACCEPT

#$IPT4 -A INPUT -p esp -m set --match-set set_ipsec src -d 0/0 -j ACCEPT
#$IPT4 -A INPUT -p ah  -m set --match-set set_ipsec src -d 0/0 -j ACCEPT

#
# Special rule for DHCP requests from LAN, which are not caught properly--------
# otherwise.
#

#$IPT4 -A INPUT -p udp --dport 67 --sport 68 -j DROP

#
# Rules for incoming packets from the internet.---------------------------------
#
echo "4.1.4 Rules for incoming packets from the internet."

$IPT4 -A INPUT -p tcp -s 0/0 -d 0/0 -j tcp_pts
$IPT4 -A INPUT -p udp -s 0/0 -d 0/0 -j udp_pts
$IPT4 -A INPUT -p icmp -s 0/0 -d 0/0 -j icmp_pts

#
# If you have a Microsoft Network on the outside of your firewall, you may
# also get flooded by Multicasts. We drop them so we do not get flooded by
# logs
#

$IPT4 -A INPUT -p all -s 0/0 -d 224.0.0.0/8 -j DROP
#$IPT4 -A INPUT -p all -d 239.255.255.250 -j DROP

#
# Log weird packets that don't match the above.
#

$IPT4 -A INPUT -p all -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT INPUT died: "

#-------------------------------------------------------------------------------
# 4.1.5 FORWARD chain---Проходящий мимо траффик---------------------------------
#-------------------------------------------------------------------------------
echo "4.1.5 FORWARD chain"
#
# Здесь правила для отладки ----------------------------------------------------
#

#
# Bad TCP packets we don't want-------------------------------------------------
#
echo "4.1.5 Bad TCP packets we don't want"
#$IPT4 -A FORWARD -p all -j black_list
#$IPT4 -A FORWARD -p tcp -j bad_tcp

#
# Accept the packets we actually want to forward--------------------------------
#

#$IPT4 -A FORWARD -p all -m state --state ESTABLISHED,RELATED -j ACCEPT

#-------------------------------------------------------------------------------
# DMZ section ------------------------------------------------------------------
#-------------------------------------------------------------------------------
echo "4.1.5 DMZ section"

#-------------------------------------------------------------------------------
# LAN section ------------------------------------------------------------------
#-------------------------------------------------------------------------------
echo "4.1.5 LAN section"

#
# Log weird packets that don't match the above.---------------------------------
#

#$IPT4 -A FORWARD -p all -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT FORWARD died: "

#-------------------------------------------------------------------------------
# 4.1.6 OUTPUT chain ---Траффик от ЛОКАЛЬНЫХ процессов--------------------------
#-------------------------------------------------------------------------------
echo "4.1.6 OUTPUT chain"
#
# Здесь правила для отладки ----------------------------------------------------
#

#
# Bad TCP packets we don't want.------------------------------------------------
#
echo "4.1.6 Bad TCP packets we don't want."
$IPT4 -A OUTPUT -p tcp -j bad_tcp

#
# Special OUTPUT rules to decide which IP's to allow.---------------------------
#

$IPT4 -A OUTPUT -p all -s $LO_IP4_RANGE -j ACCEPT
#$IPT4 -A OUTPUT -p all -s $LAN_PRI_IP4_ADDR -j ACCEPT
$IPT4 -A OUTPUT -p all -s $PUBLIC_IP4_ADDR -j ACCEPT
#$IPT4 -A OUTPUT -p all -s $OVPN_IP4_ADDR -j ACCEPT

#
# Log weird packets that don't match the above.---------------------------------
#

$IPT4 -A OUTPUT -p all -m limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "IPT OUTPUT died: "

######--------------------------------------------------------------------------
######--------------------------------------------------------------------------
# 4.2 nat table
#
echo "4.2 nat table"
#
# 4.2.1 Set policies
#
echo "4.2.1 Set policies"
#
# 4.2.2 Create user specified chains
#
echo "4.2.2 Create user specified chains"
#
# 4.2.3 Create content in user specified chains
#
echo "4.2.3 Create content in user specified chains"
#
# 4.2.4 PREROUTING chain--------------------------------------------------------
#
echo "4.2.4 PREROUTING chain"

#
# 4.2.5 POSTROUTING chain-------------------------------------------------------
#
echo "4.2.5 POSTROUTING chain"

#
# Enable simple IP Forwarding and Network Address Translation-------------------
#

#
# 4.2.6 OUTPUT chain------------------------------------------------------------
#
echo "4.2.6 OUTPUT chain"

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
