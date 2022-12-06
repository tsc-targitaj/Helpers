#!/bin/sh

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

$IPSET flush

#service fail2ban restart
#systemctl restart fail2ban.service
