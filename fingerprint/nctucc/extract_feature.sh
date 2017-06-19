#!/bin/bash

for file in /data/disk_d/BotnetDataset/category/NCTUComputerCenter/*
do
 echo $file
 python3 /home/rossy/dnsFeature/dnsFeatures.py ${file}
done

#merge
flag = 0
for file in ./*_sgl.csv
    do
        if [$flag -gt 0]
            then 
            head -n 1 ${file} > NCTUCC_all.csv
            $flag = 1
        fi
        echo ${file}
        tail -n +2 ${file} >> NCTUCC_all.csv
    done

rm ./*_sgl.csv
rm ./*_dns.txt

#cut
head -n 20000 NCTUCC_all.csv > n_top20k_all.csv 
head -n 1 NCTUCC_all.csv > n_last30k_all.csv
tail -n +20001 NCTUCC_all.csv >> n_last30k_all.csv

python3 /home/rossy/dnsFeature/fingerprint/convDNS_fp45.py n_top20k_all.csv
python3 /home/rossy/dnsFeature/fingerprint/convDNS_fp45.py n_last30k_all.csv

python3 ./n_train_sklearn.py n_top20k_all.csv n_last30k_all.csv

