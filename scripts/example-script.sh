#!/bin/sh

CONTAINER=$1

mkdir $CONTAINER/tmp
mkdir $CONTAINER/usr
mkdir $CONTAINER/etc

cp -r /bin $CONTAINER
cp -r /sbin $CONTAINER
cp -r /lib $CONTAINER
cp -r /lib64 $CONTAINER
cp -r /usr/lib $CONTAINER/usr
cp -r /usr/bin $CONTAINER/usr
cp -r /usr/sbin $CONTAINER/usr
