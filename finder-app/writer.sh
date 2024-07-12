#!/bin/bash

writefile=$1
writestr=$2

if [ $# -lt 2 ]; then
    echo "writefile: $writefile, writestr: $writestr"
    exit 1
fi 

mkdir -p "$(dirname $writefile)"
echo $writestr > $writefile

exit 0