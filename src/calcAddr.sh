#!/bin/bash

# make it single hex number (reverse byte order)
p="$4$3$2$1"

# make sure everything is uppercase or bc won't like it
p2=`echo "$p" | tr 'a-z' 'A-Z'`

#echo "Using previous EBP=$p2, the right address is:"

res=`echo "obase=16 ; ibase=16 ; $p2 -50 -4C" | bc -l `
#echo "res = $res"

# now extract the individual bytes
b1=${res:0:2}
b2=${res:2:2}
b3=${res:4:2}
b4=${res:6:2}

# echo "in reverse and separated order:"
echo "$b4 $b3 $b2 $b1"
