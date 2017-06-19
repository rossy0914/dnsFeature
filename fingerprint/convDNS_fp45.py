import argparse
import sys
import time
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
    parser.add_argument("csv", default=None, help='specify the _sgl.csv file you want to process')
    parser.add_argument("-f", "--folder", default=None, help='specify the folder you want to place the labeled flows')
    parser.add_argument("--keep", help="store all generated files", action="store_true")

    args = parser.parse_args()
    return args

def import_data(in_file):
    
    reader = csv.reader(open(in_file, 'r'))
    
    '''
    query & response pair based:

    [0]sender [1]dnsIP [2]query # [3]answer #(A record #, distinct IPs) [4]ns #
    [5]qry type [6]rcode [7]truncated flag [8]resp packet size [9]domain name len
    [10]time delay btw qry & resp
    
    [11]success sign(rcode==0) [12]NXdomain
    [13]distinct ASN# [14]distinct countries [15]distinct networks
    [16]TTL avr [17]TTL std [18]distinct TTL # [19]total TTL # [20-25]% of specific range of TTL
    [26]distance between IPs [27]timezone entropy of ip 
    #[28]number of domains share ip with [29]reverse dns query
    [28]label for bot [29]exact time of query time [30]domain name queried
    '''
    ori_list = []

    for line in reader:
        
        ori_list.append(line)
     
    del ori_list[0]
    #print(ori_list) 
    return ori_list

def convolution_domain(ori_list,out_file):
    
    fw = open(out_file,'w')

    conv_size = 45
    conv_dict = {}
    curr_list = []
    result_list = []

    ori_list.sort(key = lambda x : x[31])
    
    for line in ori_list:
        
        if len(line)>32:
            print("len=",len(line),line)
            continue

        #print(line)
        key = line[0]  # choose which column to be the key
        conv_dict[key] = conv_dict.get(key,[])
        
        if line[28] == 'True':
            label = 1
        else:
            label = 0
        
        
        if line[29]:
            hour = int(time.localtime(int(line[29].split(".")[0]))[3])
        else:
            print("no time",line)
            continue
        period = ""
        if hour >=6  and hour < 12:
            period = "m" #morning
        elif hour >=12 and hour < 18:
            period = "a" #afternoon
        else:
            period = "n" #night
        newline = [int(line[2]),int(line[3]),int(line[4]),int(line[5]),int(line[6]),int(line[7]),\
                    int(line[8]),int(line[9]),float(line[10]),int(line[11]),int(line[12]),\
                    int(line[13]),int(line[14]),int(line[15]),float(line[16]),float(line[17]),\
                    int(line[18]),int(line[19]),round(float(line[20]),2),round(float(line[21]),2),round(float(line[22]),2),\
                    round(float(line[23]),2),round(float(line[24]),2),round(float(line[25]),2),round(float(line[26]),2),round(float(line[27]),2),\
                    line[5],line[6],line[7],line[11],line[12],period,hour,label,line[0]]
        conv_dict[key].append(newline)
        
    for key in conv_dict:
        for ptr in range(0,len(conv_dict[key])+1-conv_size):
            curr_list = [a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p+q+r+s+t+u+v+w+x+y+z+a1+b1+c1+d1+e1+f1+g1+h1+i1+j1+k1+l1+m1+n1+o1+p1+q1+r1+s1 for
            a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a1,b1,c1,d1,e1,f1,g1,h1,i1,j1,k1,l1,m1,n1,o1,p1,q1,r1,s1
            in
            zip(conv_dict[key][ptr][:-1],conv_dict[key][ptr+1][:-1],conv_dict[key][ptr+2][:-1],conv_dict[key][ptr+3][:-1],conv_dict[key][ptr+4][:-1],\
            conv_dict[key][ptr+5][:-1],conv_dict[key][ptr+6][:-1],conv_dict[key][ptr+7][:-1],conv_dict[key][ptr+8][:-1],conv_dict[key][ptr+9][:-1],\
            conv_dict[key][ptr+10][:-1],conv_dict[key][ptr+11][:-1],conv_dict[key][ptr+12][:-1],conv_dict[key][ptr+13][:-1],conv_dict[key][ptr+14][:-1],\
            conv_dict[key][ptr+15][:-1],conv_dict[key][ptr+16][:-1],conv_dict[key][ptr+17][:-1],conv_dict[key][ptr+18][:-1],conv_dict[key][ptr+19][:-1],\
            conv_dict[key][ptr+20][:-1],conv_dict[key][ptr+21][:-1],conv_dict[key][ptr+22][:-1],conv_dict[key][ptr+23][:-1],conv_dict[key][ptr+24][:-1],\
            conv_dict[key][ptr+25][:-1],conv_dict[key][ptr+26][:-1],conv_dict[key][ptr+27][:-1],conv_dict[key][ptr+28][:-1],conv_dict[key][ptr+29][:-1],\
            conv_dict[key][ptr+30][:-1],conv_dict[key][ptr+31][:-1],conv_dict[key][ptr+32][:-1],conv_dict[key][ptr+33][:-1],conv_dict[key][ptr+34][:-1],\
            conv_dict[key][ptr+35][:-1],conv_dict[key][ptr+36][:-1],conv_dict[key][ptr+37][:-1],conv_dict[key][ptr+38][:-1],conv_dict[key][ptr+39][:-1],\
            conv_dict[key][ptr+40][:-1],conv_dict[key][ptr+41][:-1],conv_dict[key][ptr+42][:-1],conv_dict[key][ptr+43][:-1],conv_dict[key][ptr+44][:-1],\
                        )]
            for i in range(26):
                curr_list[i] = curr_list[i]/45

            if curr_list[-1] >= 1:
                curr_list[-1] = 'Bot'
            else:
                curr_list[-1] = 'Normal'
            
            curr_list.append(key)
            #print(curr_list)
            
            result_list.append(curr_list)
            '''
            
            '''
    
    feature_sel = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,34]
    feature_name = ["qryNum","ansNum","nsNum","qryType","rcode","trunFlag","respPktSize","domNameLen","respTime",\
        "success","nxDomain","distASN","distCountry","distNet","meanTTL","stdTTL","distTTL","totalTTL","TTL0","TTL1","TTL10","TTL100","TTL300","TTL900up",\
        "distanceBtwIP","entTimezone",\
        "qryType Seq","rcode Seq","trun flag Seq","success Seq","NXDomain Seq","period","hour","label","ip"]

    for i in feature_sel:
        fw.write("%s," % feature_name[i])
    fw.write("0\n")

    for line in result_list:
        for i in feature_sel:
            fw.write("%s," % line[i])     
        fw.write("0\n")

    for i in conv_dict:
        print(i)
        print(len(conv_dict[i]))
        print('=====')
    
    print('total line: ', len(ori_list))

def main():
    args = getopt()
    cname = args.csv.rsplit('.csv')[0].split('/')[-1]
    
    if args.folder:
        folder = args.folder.strip('/') + '/' + pname + '/'
    else:
        folder = './'
                     
    if not os.path.exists(folder):
        os.makedirs(folder)
                           
    #Produce _dns.txt file
    time1 = timeit.default_timer()
    output_name = folder + cname + '_fp45_mean.csv'
    origin = import_data(args.csv)
    convolution_domain(origin,output_name)
    time2 = timeit.default_timer()
    print("time: ",time2-time1)

if __name__ == "__main__":
    main()
