#!/bin/sh
# $Id: arping-scan-net.sh 859 2003-04-07 17:38:44Z marvin $
#
#  Copyright (C) 2002 Thomas Habets <thomas@habets.pp.se>
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public
#  License as published by the Free Software Foundation; either
#  version 2 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#

trap "exit 0" INT

if [ "$1" = "" ]; then
	echo
	echo "Usage: $0 <mac address>"
	echo ""
	echo "   Sorry, it's not more configurable than that, edit the source"
	echo
	exit 1
fi
TARGET_MAC="$1"

#
# first number after 'seq' is range start, second is range end
#
# default is [192-192].[168-168].[0-0].[0-255]
#
#
# I may put this functionality into ARPing one day if people seem to like it.
#
for a in $(seq 192 192); do
    for b in $(seq 168 168); do
	for c in $(seq 42 42); do
	    for d in $(seq 0 255); do
		sh -c "arping -q -c 1 -T $a.$b.$c.$d $TARGET_MAC -A
		if [ \$? == 0 ]; then
		    echo Got answer with address: $a.$b.$c.$d
		fi" &
	    done
	    wait
	done
    done
done
exit 1
