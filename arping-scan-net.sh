#!/bin/sh
# $Id: arping-scan-net.sh 546 2002-02-12 18:17:47Z marvin $
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

TARGET_MAC="0:60:93:34:91:99"

if [ "$1" != "" ]; then
    TARGET_MAC="$1"
fi

#
# first number after 'seq' is range start, second is range end
#
# default is [192-192].[168-168].[0-0].[0-255]
#
#
# If you think this is useful, tell me and I'll incorperate it into arping
#
for a in $(seq 192 192); do
    for b in $(seq 168 168); do
	for c in $(seq 0 0); do
	    for d in $(seq 0 255); do
		arping -q -c 1 -T $a.$b.$c.$d $TARGET_MAC
		if [ $? == 0 ]; then
		    echo "Got answer with address: $a.$b.$c.$d"
		fi
	    done
	done
    done
done
exit 1
