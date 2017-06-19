#!/bin/bash

for file in /home/rossy/dnsFeature/fingerprint/ourlabtraffic/capture*_sgl.csv
    do
        echo ${file}
        tail -n +2 ${file} >> ourlabtraffic_all_sgl.csv
    done
