import argparse
import sys
import timeit
import os
import re
import subprocess
import math
import statistics as st
import numpy as np
from collections import Counter
import pyasn
import ipwhois
from geolite2 import geolite2
import ipaddress
import tldextract
import csv

from fingerprint import convDNS_fp50

def getopt():
    parser = argparse.ArgumentParser(description='convert pcap file to get DNS features ')
    parser.add_argument("pcap", default=None, help='specify the pcap file you want to process')
    parser.add_argument("-f", "--folder", default=None, help='specify the folder you want to place the labeled flows')
    parser.add_argument("--keep", help="store all generated files", action="store_true")

    args = parser.parse_args()
    return args

def calc_ent(x):

    """
    calculate shanno ent of an array
    """

    x_value_list = set([x[i] for i in range(x.shape[0])])
    ent = 0.0                              
                                    
    for x_value in x_value_list:
        p = float(x[x == x_value].shape[0]) / x.shape[0]
        logp = np.log2(p)
        ent -= p * logp
                       
    return ent

def entropy(string):
    "Calculates the Shannon entropy of a string"
    
    # get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    
    # calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

    return entropy

def entropy_ideal(length):
    
    "Calculates the ideal Shannon entropy of a string with given length"
                                                               
    prob = 1.0 / length
    
    return -1.0 * length * prob * math.log(prob) / math.log(2.0)

def avg_distance(ip_list):
    distance = []
    for i in range(len(ip_list)):                 
        for j in range(i+1,len(ip_list)):
            ip1 = ipaddress.ip_address(ip_list[i])
            ip2 = ipaddress.ip_address(ip_list[j])
            distance.append(abs(int(ip1)-int(ip2)))
    #print(distance)
    return np.mean(distance)

def pcap2txt(pcap_file, txt_file):

    cmd = "tshark -Y 'dns && not icmp' -r %s -e frame.time_epoch \
            -e ip.src -e ip.dst -e frame.len \
            -e dns.id -e dns.a -e dns.cname -e dns.time \
            -e dns.qry.type -e dns.qry.name.len \
            -e dns.flags.response -e dns.flags.rcode \
            -e dns.resp.ttl \
            -e dns.count.queries -e dns.count.answers\
            -T fields -E separator=';' > %s" %(pcap_file, txt_file) #seperator","
            
    print(cmd)
    subprocess.call(cmd, shell=True)

def feature(in_file):
    
    fp = open(in_file, 'r')

    asndb = pyasn.pyasn('/home/rossy/dnsFeature/ipasn_20160918.dat') 

    args = getopt()
    pname = args.pcap.rsplit('.pcap')[0].split('/')[-1]
    out_file = pname + '_sgl.csv'

    fw = open(out_file, 'w')


    ''' 
            [0]frame.time_epoch [1]ip.src [2]ip.dst [3]frame.len \
            [4]dns.id [5]dns.a [6]dns.cname [7]dns.time \
            [8]dns.qry.type [9]dns.qry.name.len \
            [10]dns.flags.response [11]dns.flags.rcode \
            [12]dns.resp.ttl \
            [13]dns.count.queries [14]dns.count.answers\
    '''
    
    dns_dict = dict()

    for line in fp:
        
        items = line.strip().split(';')
        
        try:
            items[0]
        except:
            print("null: ",line)
            continue

        if ((len(items[1]) > 25) or (len(items[2]) > 25)): #more than 1 IP addr. in src or dst
            print("ip length error: ",line)
            continue
        
        respFlag = items[10]
        if respFlag == '0':
            sender = items[1]
            dnsIP = items[2]  # dns server
            qryTime = items[0]
        elif respFlag == '1':
            sender = items[2]
            dnsIP = items[1]
        payload = int(items[3]) # payload size
        dnsid = items[4] 
        
        ans = []
        if items[5]:
            ans = items[5].strip().split(',')   
        cname = items[6]
        if items[7]:
            respTime = float(items[7])
        else:
            respTime = 0
        qryType = items[8]
        if items[9]:
            domainLen = int(items[9].replace(",",""))
        else:
            domainLen = 0
        rcode = items[11] # return code: 0-no error, 2-server error, 3-NXDomain
        ttl = []
        if items[12]:
            ttl = items[12].strip().split(',')
        if items[13]:
            qryNum = int(items[13])
        else:
            print("no qry: ",line)
            continue
        if items[14]:
            ansNum = int(items[14])

        '''

        query & response pair based:

        [0]sender [1]dnsIP [2]query # [3]answer #(A record #, distinct IPs) 
        [4]qry type [5]rcode [6]resp packet size [7]domain name len
        [8]time delay btw qry & resp
        
        [9]success sign(rcode==0) [10]NXdomain
        [11]distinct ASN# [12]distinct countries [13]distinct networks
        [14]TTL avr [15]TTL std [16]distinct TTL # [17]total TTL # [18-23]% of specific range of TTL
        [24]distance between IPs [25]timezone entropy of ip 
        [26]exact time of query time 
        '''
        feature_sel = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]
        feature_name = ["sIP","dIP","qryNum","ansNum","nsNum","qryType","rcode","trunFlag","respPktSize","domNameLen","respTime",\
        "success","nxDomain","distASN","distCountry","distNet","meanTTL","stdTTL","distTTL","totalTTL","TTL0","TTL1","TTL10","TTL100","TTL300","TTL900up",\
        "distanceBtwIP","entTimezone",\
        "queryTime"]
        

        dns_dict[dnsid] = dns_dict.get(dnsid,[sender,dnsIP,0,0,0,0,0,domainLen,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,""])
        
        if respFlag == '0':
            dns_dict[dnsid][26] = qryTime
            dns_dict[dnsid][2] = qryNum
            if qryType:
                dns_dict[dnsid][4] = qryType
        else:
            dns_dict[dnsid][3] = ansNum
            dns_dict[dnsid][6] = payload
            dns_dict[dnsid][5] = rcode
            dns_dict[dnsid][8] = respTime
            
        
        if rcode == '0':
            dns_dict[dnsid][11] = 1 #success
        elif rcode == '3':
            dns_dict[dnsid][12] = 1 #NXdomain

        asn = []
        net = []
        countries = []
        timezones = []
        
        if ans: 
            for ip in ans:
                asn.append(asndb.lookup(ip)[0])
                net.append(asndb.lookup(ip)[1])
                obj = geolite2.reader().get(ip)
                if obj:
                    if obj.get('country'):   
                        countries.append(obj['country']['iso_code'])
                    if obj['location'].get('time_zone'):   
                        timezones.append(obj['location'].get('time_zone'))
                
        dns_dict[dnsid][11] = len(set(asn))
        dns_dict[dnsid][12] = len(set(countries))
        dns_dict[dnsid][13] = len(set(net))
        if len(ans) > 1:
            dns_dict[dnsid][24] = avg_distance(ans)
        dns_dict[dnsid][25] = calc_ent(np.array(timezones))    
        
        if ttl:
            ttl_cnt = [0,0,0,0,0,0]
            for t in range(len(ttl)):
                ttl[t] = int(ttl[t])
                if ttl[t] >= 0 and ttl[t] < 1:
                    ttl_cnt[0] += 1
                elif ttl[t] < 10:
                    ttl_cnt[1] += 1
                elif ttl[t] < 100:
                    ttl_cnt[2] += 1
                elif ttl[t] < 300:
                    ttl_cnt[3] += 1
                elif ttl[t] < 900:
                    ttl_cnt[4] += 1
                elif ttl[t] >= 900:
                    ttl_cnt[5] += 1
            dns_dict[dnsid][14] = np.mean(ttl)
            dns_dict[dnsid][15] = np.std(ttl)
            dns_dict[dnsid][16] = len(set(ttl))
            dns_dict[dnsid][17] = len(ttl)
            for n in range(len(ttl_cnt)):
                dns_dict[dnsid][18+n] = ttl_cnt[n] / len(ttl)
        else:
            for n in range(14,24):
                dns_dict[dnsid][n] = 0

    for i in feature_sel:
        string = ",".join(i) + '\n'
    fw.write(string)

    for key in sorted(dns_dict,key = lambda x : dns_dict[x][26]):
        if dns_dict[key][7]>0 :
            for i in feature_sel:
                string = ",".join(dns_dict[key][i])+'\n' 
            fw.write(string)

    fp.close()
    fw.close()

    return out_file

def main():
    args = getopt()
    pname = args.pcap.rsplit('.pcap')[0].split('/')[-1]
    
    if args.folder:
        folder = args.folder.strip('/') + '/' + pname + '/'
    else:
        folder = './'
                     
    if not os.path.exists(folder):
        os.makedirs(folder)
                           
    #Produce _dns.txt file
    time1 = timeit.default_timer()
    txt_name = folder + pname + '_dns.txt'
    pcap2txt(args.pcap, txt_name)
    time2 = timeit.default_timer()
    print("Tshark time cost:",time2-time1)
    
    #Extract features
    sgl_name = feature(txt_name)
    time3 = timeit.default_timer()
    print("Feature extracted. Time cost:",time3-time2)

    #Convolution, size=50
    fp_name = folder + pname + '_fp50_mean.csv'
    convDNS_fp50.convolution(sgl_name,fp_name)
    time4 = timeit.default_timer()
    print("Convoluted. Time cost:",time4-time3)

    
if __name__ == "__main__":
    main()
