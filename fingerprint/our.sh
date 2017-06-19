#!/bin/bash

#for file in /data/disk_d/ourlab_traffic/ourlab_traffic/ourlab_traffic* 
for file in /data/disk_d/BotnetDataset/category/NCTUComputerCenter/* 
do
 if test -d $file
 then echo $file
 		python3 ../../dnsFeatures.py ${file}
        echo "finish sgl"
        python3 ../convDNS_fp45.py ./*_sgl.csv
        echo "finish fp"
	fi
	done
	
