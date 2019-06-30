#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 29 18:08:44 2019

@author: Karlen Avogian
"""

import os
import re
import pandas as pd

hexdumps = os.listdir()
flows = []
for file in hexdumps:
    #get only UDP and TCP flows
    if(re.search('.+\.pcap', file)):
        print('Reading', file)
        flow_features = []
        with open(file,'r') as reader:
            counter = 0
            packet_features = []
            for line in reader:
                if line == '\n':
                    counter += 1
                    packet_features = packet_features[16:]
                    
                    if len(packet_features) >= 160:
                        packet_features = packet_features[:160]
                        
                    elif len(packet_features) < 160:
                        while(len(packet_features) != 160):
                            packet_features.append(0)
                            
                    flow_features.append(packet_features)
                    packet_features = []
                    
                elif line != '\n' :
                    pattern = '[0-9a-f][0-9a-f][0-9a-f][0-9a-f]  (.*  ) .*'
                    match = re.match(pattern,line)
                    hex_line = match.group(1).split()
                    for hex_number in hex_line:
                        packet_features.append(int(hex_number,16))
              
                # We need only max 10 packets per flow
                if counter == 10:
                    break
                
            while counter < 10:
                packet_features = [0 for i in range(160)]
                flow_features.append(packet_features)
                counter += 1
            
            feature_vector = [item for sublist in flow_features for item in sublist]
            flows.append(feature_vector)

df = pd.DataFrame(flows)
df.to_csv('./flow_feature_vectors.csv',sep=',', index=False,header=False)
print('Done')
