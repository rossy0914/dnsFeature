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
            -e dns.id -e dns.a -e dns.cname -e dns.ns -e dns.time \
            -e dns.qry.name -e dns.qry.type -e dns.qry.name.len \
            -e dns.flags.response -e dns.flags.rcode -e dns.flags.truncated \
            -e dns.resp.ttl -e dns.resp.name \
            -e dns.count.queries -e dns.count.answers\
            -T fields -E separator=';' > %s" %(pcap_file, txt_file) #seperator","
            
    print(cmd)
    subprocess.call(cmd, shell=True)

def feature(in_file):
    
    fp = open(in_file, 'r')

    asndb = pyasn.pyasn('/home/rossy/dnsFeature/ipasn_20160918.dat') 

    reader = csv.reader(open('/home/rossy/dnsFeature/top-1m.csv', 'r'))
    topSites_list = {}
    for line in reader:
        #print(line[1])
        topSites_list[line[1]] = line[0]
    
    args = getopt()
    pname = args.pcap.rsplit('.pcap')[0].split('/')[-1]
    out_file = pname + '_sgl.csv'
    out_file2 = pname + '_domain.txt'

    fw = open(out_file, 'w')
    #fw2 = open(out_file2, 'w')


    ''' 
            [0]frame.time_epoch [1]ip.src [2]ip.dst [3]frame.len \
            [4]dns.id [5]dns.a [6]dns.cname [7]dns.ns [8]dns.time \
            [9]dns.qry.name [10]dns.qry.type [11]dns.qry.name.len \
            [12]dns.flags.response [13]dns.flags.rcode [14]dns.flags.truncated \
            [15]dns.resp.ttl [16]dns.resp.name \
            [17]dns.count.queries [18]dns.count.answers\
    '''
    
    dns_dict = dict()
    domain_dict = dict()

    for line in fp:
        
        #print("----------")
        #print(line)
        
        items = line.strip().split(';')
        
        try:
            items[0]
        except:
            print("null: ",line)
            continue

        if ((len(items[1]) > 25) or (len(items[2]) > 25)):
            print("ip length: ",line)
            continue
        if "<" in items[9]:
            print("contains \'<\' :", line)
            continue
        
        respFlag = items[12]
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
        ns = items[7] # name server
        if items[8]:
            respTime = float(items[8])
        else:
            respTime = 0
        qryName = items[9] # domain name queried
        qryType = items[10]
        if items[11]:
            domainLen = int(items[11].replace(",",""))
        else:
            domainLen = 0
        rcode = items[13] # return code: 0-no error, 2-server error, 3-NXDomain
        truncated = items[14]
        ttl = []
        if items[15]:
            ttl = items[15].strip().split(',')
        respName = items[16]
        if items[17]:
            qryNum = int(items[17])
        else:
            print("no qry: ",line)
            continue
        if items[18]:
            ansNum = int(items[18])

        '''

        query & response pair based:

        [0]sender [1]dnsIP [2]query # [3]answer #(A record #, distinct IPs) [4]ns #
        [5]qry type [6]rcode [7]truncated flag [8]resp packet size [9]domain name len
        [10]time delay btw qry & resp
        
        [11]success sign(rcode==0) [12]NXdomain
        [13]distinct ASN# [14]distinct countries [15]distinct networks
        [16]TTL avr [17]TTL std [18]distinct TTL # [19]total TTL # [20-25]% of specific range of TTL
        [26]distance between IPs [27]timezone entropy of ip [28]number of domains share ip with [29]reverse dns query
        [30]label for bot [31]exact time of query time [32]domain name queried
        '''
        feature_sel = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,30,31,32]
        feature_name = ["sIP","dIP","qryNum","ansNum","nsNum","qryType","rcode","trunFlag","respPktSize","domNameLen","respTime",\
        "success","nxDomain","distASN","distCountry","distNet","meanTTL","stdTTL","distTTL","totalTTL","TTL0","TTL1","TTL10","TTL100","TTL300","TTL900up",\
        "distanceBtwIP","entTimezone","domainNumPerIP","reverseDNS",\
        "bot","queryTime","qryName"]
        #To be done:[21,23,24]
        

        if ("Zeus" in pname or "zeroaccess" in pname or "Conficker" in pname or "Citadel" in pname or "Virut" in pname
            or "sogou" in pname or "smoke" in pname or "bot" in pname): 
            dns_dict[dnsid] = dns_dict.get(dnsid,[sender,dnsIP,0,0,0,0,0,0,0,domainLen,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,True,"",qryName])
        else:
            dns_dict[dnsid] = dns_dict.get(dnsid,[sender,dnsIP,0,0,0,0,0,0,0,domainLen,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,False,"",qryName])
        
        if respFlag == '0':
            dns_dict[dnsid][31] = qryTime
            dns_dict[dnsid][2] = qryNum
            if qryType:
                dns_dict[dnsid][5] = qryType
        else:
            dns_dict[dnsid][3] = ansNum
            dns_dict[dnsid][8] = payload
            dns_dict[dnsid][6] = rcode
            dns_dict[dnsid][10] = respTime
            dns_dict[dnsid][7] = truncated
            
        
        if rcode == '0':
            dns_dict[dnsid][11] = 1 #success
        elif rcode == '3':
            dns_dict[dnsid][12] = 1 #NXdomain

        #print(qryName)
        if tldextract.extract(qryName).registered_domain in topSites_list:
            #print("top sites:",topSites_list[tldextract.extract(qryName).registered_domain])
            if int(topSites_list[tldextract.extract(qryName).registered_domain])<=500:
                dns_dict[dnsid][30] = False
        
        asn = []
        net = []
        countries = []
        timezones = []
        #print(ans)
        
        #print(geolite2.reader().get('207.109.221.179'))

        if ans: 
            for ip in ans:
                #print("ip:",ip)
                #print(asndb.lookup(ip))
                asn.append(asndb.lookup(ip)[0])
                net.append(asndb.lookup(ip)[1])
                obj = geolite2.reader().get(ip)
                if obj:
                    if obj.get('country'):   
                        countries.append(obj['country']['iso_code'])
                    if obj['location'].get('time_zone'):   
                        timezones.append(obj['location'].get('time_zone'))
                
                #obj = ipwhois.IPWhois(ip)
                #obj2 = ipwhois.net.Net(ip)
                #print(obj.lookup())
                #print(obj.lookup_whois(get_referral=True))
                #countries.append(obj.lookup_whois()['nets'][0]['country'])
                #print(obj2.get_asn_whois())
                #print(qryName, obj2.get_host())
                #try:
                    #data = socket.gethostbyaddr(ip)
                    #host = repr(data[0])
                    #print(host)                       
                #except Exception:
                    # fail gracefully
                    #print('failed')

        
        dns_dict[dnsid][13] = len(set(asn))
        dns_dict[dnsid][15] = len(set(net))
        #print('distinct asn: ', len(set(asn)))
        #print('distinct net: ', len(set(net)))
        #print(countries)
        #print('distinct countries: ',len(set(countries)))
        dns_dict[dnsid][14] = len(set(countries))
        #print(timezones)
        dns_dict[dnsid][27] = calc_ent(np.array(timezones))    
        #print('timezone entropy: ',dns_dict[dnsid][27])
        if len(ans) > 1:
            dns_dict[dnsid][26] = avg_distance(ans)
        #print('distance mean: ',dns_dict[dnsid][26])
        

        #print("ttl:",ttl)
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
            dns_dict[dnsid][16] = np.mean(ttl)
            dns_dict[dnsid][17] = np.std(ttl)
            dns_dict[dnsid][18] = len(set(ttl))
            dns_dict[dnsid][19] = len(ttl)
            #print('ttl count: ',ttl_cnt)
            for n in range(len(ttl_cnt)):
                dns_dict[dnsid][20+n] = ttl_cnt[n] / len(ttl)
        else:
            for n in range(16,26):
                dns_dict[dnsid][n] = 0
    
        #print(dns_dict[dnsid])
        
        '''
        domain based
        
        key: domain name
        1. statistic:
        [0]distinct ip # [1]total ip # [2]avg distance btw ips 
        [3]distinct senders [4]distinct sender asn
        [5]total query num
        [6]domain name length [7]entropy fo domain name 
        [8]answer list [9]sender list [10]asn list
        
        2.linguistics
        []
        
        '''
        '''
        feature_sel2 = [0,1,2,3,4,5,6,7]
        
        domain_dict[qryName] = domain_dict.get(qryName,[0,0,0,0,0,0,0,0,[],[],[]])
    
        domain_dict[qryName][8].extend(ans)
        domain_dict[qryName][0] = len(set(domain_dict[qryName][8]))
        domain_dict[qryName][1] = len(domain_dict[qryName][8])
        if len(domain_dict[qryName][8]) > 1:
            domain_dict[qryName][2] = avg_distance(domain_dict[qryName][8])
        domain_dict[qryName][9].append(sender)
        domain_dict[qryName][3] = len(set(domain_dict[qryName][9]))
        if "192.168" in sender:
            domain_dict[qryName][10].append("None")
        else:
            domain_dict[qryName][10].append(asndb.lookup(sender)[0])
        domain_dict[qryName][4] = len(domain_dict[qryName][10])
        domain_dict[qryName][5] += qryNum
        domain_dict[qryName][6] = domainLen
        if qryName:
            domain_dict[qryName][7] = entropy(qryName)
        


        print(qryName,domain_dict[qryName])
        if qryName:
            print("entropy of domain name: ", entropy(qryName))
            #print("ideal entropy of same length string: ", entropy_ideal(domainLen))
    
        '''
    
    

    for i in feature_sel:
        fw.write("%s," % feature_name[i])
    fw.write("0\n")

    for key in sorted(dns_dict,key = lambda x : dns_dict[x][31]):
        if dns_dict[key][9]>0 :
            for i in feature_sel:
                fw.write("%s," % dns_dict[key][i])    #%s 
            fw.write("0\n")
    '''
    for key in domain_dict:
        if key:
            for i in feature_sel2:
                fw2.write("%s," % domain_dict[key][i])
            fw2.write("\n")
    '''
    fp.close()
    fw.close()
    #fw2.close()

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

    feature(txt_name)

if __name__ == "__main__":
    main()
