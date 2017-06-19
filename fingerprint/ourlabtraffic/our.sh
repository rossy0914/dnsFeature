#!/bin/bash

for dir in /data/disk_d/ourlab_traffic/ourlab_traffic/ourlab_traffic* 
  do
    for file in ${dir}/ourlab*
    do
     echo $file
     python3 /home/rossy/dnsFeature/dnsFeatures.py ${file}
     
    done
  done

#merge
flag = 0
for file in ./*_sgl.csv
    do
        if [$flag -gt 0]
            then 
            head -n 1 ${file} > ourlab_all.csv
            $flag = 1
        fi
        echo ${file}
        tail -n +2 ${file} >> ourlab_all.csv
    done

rm ./*_sgl.csv
rm ./*_dns.txt


#cut
#head -n 35000 NCTUCC_all.csv > n_top35k_all.csv 
#head -n 1 NCTUCC_all.csv > n_last15k_all.csv
#tail -n +35001 NCTUCC_all.csv >> n_last15k_all.csv

#python3 /home/rossy/dnsFeature/fingerprint/convDNS_fp45.py n_top20k_all.csv
#python3 /home/rossy/dnsFeature/fingerprint/convDNS_fp45.py n_last30k_all.csv

#python3 ./n_train_sklearn.py n_top20k_all.csv n_last30k_all.csv

#for csv in /home/rossy/dnsFeature/fingerprint/ourlabtraffic/*_sgl.csv
#    python3 /home/rossy/dnsFeature/convDNS.py ${csv}

