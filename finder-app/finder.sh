#!/bin/bash

filesdir=$1
searchstr=$2

if [ $# -lt 2 ]; then
    echo "filesdir: $filesdir, searchstr: $searchstr"
    exit 1
fi 

if [ ! -d "$filesdir" ]; then
    echo "filesdir is no directory: $filesdir, searchstr: $searchstr"
    exit 1
fi 

X=$(find $filesdir -type f | wc -l)

Y=$(grep -r $searchstr $filesdir | wc -l)

echo "The number of files are $X and the number of matching lines are $Y"