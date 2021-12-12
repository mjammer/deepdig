#!/bin/bash
remote=$1
pkgs=kprobe

for p in $pkgs
do 
	cd pkg/
	scp -r root@${remote}:/root/workspace/deepdig/pkg/${p}/ .
	cd -
done