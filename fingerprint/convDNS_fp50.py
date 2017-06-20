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

    [0]sender [1]dnsIP [2]query # [3]answer #(A record #, distinct IPs) 
    [4]qry type [5]rcode [6]resp packet size [7]domain name len
    [8]time delay btw qry & resp
    
    [9]success sign(rcode==0) [10]NXdomain
    [11]distinct ASN# [12]distinct countries [13]distinct networks
    [14]TTL avr [15]TTL std [16]distinct TTL # [17]total TTL # [18-23]% of specific range of TTL
    [24]distance between IPs [25]timezone entropy of ip 
    [26]exact time of query time
    '''
    ori_list = []

    for line in reader:
        ori_list.append(line)
    return ori_list

def convolution(in_file,out_file):
    
    ori_list = import_data(in_file)
    fw = open(out_file,'w')

    conv_size = 50
    conv_dict = {}
    curr_list = []
    result_list = []

    ori_list.sort(key = lambda x : x[26])
    
    for line in ori_list:
        
        if len(line) > 27:
            print("len=",len(line),line)
            continue

        #print(line)
        key = line[0]  # choose which column to be the key
        conv_dict[key] = conv_dict.get(key,[])
        
        if line[26]:
            hour = int(time.localtime(int(line[26].split(".")[0]))[3])
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
                    float(line[8]),int(line[9]),int(line[10]),\
                    int(line[11]),int(line[12]),int(line[13]),float(line[14]),float(line[15]),\
                    int(line[16]),int(line[17]),round(float(line[18]),2),round(float(line[19]),2),round(float(line[20]),2),\
                    round(float(line[21]),2),round(float(line[22]),2),round(float(line[23]),2),round(float(line[24]),2),round(float(line[25]),2),\
                    line[4],line[5],line[9],line[10],period,hour,line[0]]
        conv_dict[key].append(newline)
        
    for key in conv_dict:
        for ptr in range(0,len(conv_dict[key])+1-conv_size):
            curr_list = [a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p+q+r+s+t+u+v+w+x+y+z+a1+b1+c1+d1+e1+f1+g1+h1+i1+j1+k1+l1+m1+n1+o1+p1+q1+r1+s1+t1+u1+v1+w1+x1 for a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a1,b1,c1,d1,e1,f1,g1,h1,i1,j1,k1,l1,m1,n1,o1,p1,q1,r1,s1,t1,u1,v1,w1,x1 in
            zip(conv_dict[key][ptr][:-1],conv_dict[key][ptr+1][:-1],conv_dict[key][ptr+2][:-1],conv_dict[key][ptr+3][:-1],conv_dict[key][ptr+4][:-1],\
            conv_dict[key][ptr+5][:-1],conv_dict[key][ptr+6][:-1],conv_dict[key][ptr+7][:-1],conv_dict[key][ptr+8][:-1],conv_dict[key][ptr+9][:-1],\
            conv_dict[key][ptr+10][:-1],conv_dict[key][ptr+11][:-1],conv_dict[key][ptr+12][:-1],conv_dict[key][ptr+13][:-1],conv_dict[key][ptr+14][:-1],\
            conv_dict[key][ptr+15][:-1],conv_dict[key][ptr+16][:-1],conv_dict[key][ptr+17][:-1],conv_dict[key][ptr+18][:-1],conv_dict[key][ptr+19][:-1],\
            conv_dict[key][ptr+20][:-1],conv_dict[key][ptr+21][:-1],conv_dict[key][ptr+22][:-1],conv_dict[key][ptr+23][:-1],conv_dict[key][ptr+24][:-1],\
            conv_dict[key][ptr+25][:-1],conv_dict[key][ptr+26][:-1],conv_dict[key][ptr+27][:-1],conv_dict[key][ptr+28][:-1],conv_dict[key][ptr+29][:-1],\
            conv_dict[key][ptr+30][:-1],conv_dict[key][ptr+31][:-1],conv_dict[key][ptr+32][:-1],conv_dict[key][ptr+33][:-1],conv_dict[key][ptr+34][:-1],\
            conv_dict[key][ptr+35][:-1],conv_dict[key][ptr+36][:-1],conv_dict[key][ptr+37][:-1],conv_dict[key][ptr+38][:-1],conv_dict[key][ptr+39][:-1],\
            conv_dict[key][ptr+40][:-1],conv_dict[key][ptr+41][:-1],conv_dict[key][ptr+42][:-1],conv_dict[key][ptr+43][:-1],conv_dict[key][ptr+44][:-1],\
            conv_dict[key][ptr+45][:-1],conv_dict[key][ptr+46][:-1],conv_dict[key][ptr+47][:-1],conv_dict[key][ptr+48][:-1],conv_dict[key][ptr+49][:-1] )]
            
            for i in range(24):
                curr_list[i] = curr_list[i]/conv_size
            
            curr_list.append(key)
            #print(curr_list)
            
            result_list.append(curr_list)
            
    
    feature_sel = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]
    feature_name = ["qryNum","ansNum","qryType","rcode","respPktSize","domNameLen","respTime",\
        "success","nxDomain","distASN","distCountry","distNet","meanTTL","stdTTL","distTTL","totalTTL","TTL0","TTL1","TTL10","TTL100","TTL300","TTL900up",\
        "distanceBtwIP","entTimezone",\
        "qryType Seq","rcode Seq","success Seq","NXDomain Seq","period","hour","ip"]

    for i in feature_sel:
        string = ",".join(feature_name[i])+'\n'
    fw.write(string)

    for line in result_list:
        for i in feature_sel:
            string = ",".join(line[i])+'\n'    
        fw.write(string)

    for i in conv_dict:
        print(i)
        print(len(conv_dict[i]))
        print('=====')
    
    print('total line: ', len(result_list))

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
    output_name = folder + cname + '_fp50_mean.csv'
    convolution(args.csv,output_name)
    time2 = timeit.default_timer()
    print("time: ",time2-time1)

if __name__ == "__main__":
    main()
