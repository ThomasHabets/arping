#!/bin/sh
# arping-scan-net.sh
#
#  Copyright (C) 2002 Thomas Habets <thomas@habets.se>
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
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

# seq doesnt exist on some retarded boxen, comment out if your box is too
# stupid to have bc and/or tr
seq() { echo "for (i=$1; i<=$2; i++) i;" | bc | tr "\012" " "; }

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
	for c in $(seq 0 0); do
	    for d in $(seq 0 255); do
		sh -c "arping -A -q -c 1 -T $a.$b.$c.$d $TARGET_MAC
		if [ \$? = 0 ]; then
		    echo Got answer with address: $a.$b.$c.$d
		fi" &
	    done
	    wait
	done
    done
done
#exit 1
