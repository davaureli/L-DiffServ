# -*- coding: utf-8 -*-
"""
Created on Mon Mar 18 10:16:29 2019

@author: Davide
"""

#Reading .pcap file and search  wich kind of DSCP and TC we have

import pyshark
import os
import glob
from collections import Counter
import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np
import pyasn
from sklearn.preprocessing import MinMaxScaler

#For now we will focus on DSCP(6 bits)
#Below we have the possible values with the correspondig class of service

dscp_tab = {0: "best effort",
            8: "priority",
            10: "priority",
            12: "priority",
            14: "priority",
            16: "Immediate",
            18: "Immediate",
            20: "Immediate",
            22: "Immediate",
            24: "Flash voice",
            26: "Flash voice",
            28: "Flash voice",
            30: "Flash voice",
            32: "Flash Override",
            34: "Flash Override",
            36: "Flash Override",
            38: "Flash Override",
            40: "Critical voice RTP",
            46: "Critical voice RTP",
            48: "Internetwork control",
            56: "Network Control"
            }

'''
ecn_tab = {0b00: "Non ECN capable transport",
           0b10: "ECN capable transport 0",
           0b01: "ECN capable transport 1",
           0b11: "Congestion Encountered"
           }

ECN = []
'''

#Autonomous System detecting by Agathe in the paper Split & Merge

AS = {2500: [" 133.138.0.0/16", "133.4.128.0/18", "150.52.0.0/16", 
             "163.221.0.0/16","192.50.36.0/24", "202.0.73.0/21", 
             "202.249.0.0/18", "203.178.128.0/17"],

      2501:[" 130.69.0.0/16", "133.11.0.0/16 ", "157.82.0.0/16"],
      4608 :["203.119.96.0/20"],
       4718 :[" 210.156.0.0/22"],
       10010 :[" 202.244.160.0/18"],
       23799 :[" 202.25.80.0/21"],
       36635:["131.113.0.0/16 ", "133.27.0.0/16"] }


asndb = pyasn.pyasn('ipasn_20140513.dat')

asndb = pyasn.pyasn("IpAsn2019.dat")

#OutPut : (14618, '54.224.0.0/15')

Win =[]
Win_Scale =[]

DSCP = []
index = 0

AS_val = []

vedere =[]
 
i = 0
#All files in our cwd
for file in glob.glob("*.pcap"):
    print("Now I'm working on: " + file)
    pcap = pyshark.FileCapture(file)
    
    for packet in pcap:
        i += 1
        #print(packet[0])
        #print(dir(packet.ip.dsfield_dscp))
        if 'IP' in packet:
            AS_val.append(asndb.lookup(packet.ip.src)[0])
        else:
            pass
    pcap.close()
            try:
                Win.append(packet.tcp.window_size_value)
                Win_Scale.append(packet.tcp.window_size_scalefactor)
            except:
                pass
        elif "IPV6" in packet:
            break
        if packet.transport_layer == "UDP":
            break
            DSCP.append(packet.ip.dsfield_dscp)
             #ECN.append(packet.ip.dsfield_ecn)
        elif "IPV6" in packet:
            DSCP.append(packet.ipv6.tclass_dscp)
            
        else:
            vedere.append(packet)
            
print(index)

Counter(DSCP)
            
            if packet.ip.dsfield_dscp == "26":
                print(i)
                break


#Lavorando sulo su IPV4
i = 0 
title = ["Label DSCP", "ttl", "Protocol", "header len", "length"] 
totale = []
totale.append(title)  
for file in glob.glob("*.pcap"):
    print()
    print("Now I'm working on: " + file)
    pcap = pyshark.FileCapture(file)
    print()
    for packet in pcap:
        valori = []
        i += 1
        #print(packet[0])
        #print(dir(packet.ip.dsfield_dscp))
        if 'IP' in packet:
            #Y
            valori.append(packet.ip.dsfield_dscp)
            #Features 
            valori.append(int(packet.ip.ttl))
            valori.append(int(packet.ip.proto))
            #Tutto uguale l'header
            valori.append(int(packet.ip.hdr_len))
            valori.append(int(packet.ip.len))
            
            #valori.append(packet.ip.src)
            #valori.append(packet.ip.dst)
            
            totale.append(valori)
    pcap.close()

print(i)
        '''
             #ECN.append(packet.ip.dsfield_ecn)
        elif "IPV6" in packet:
            DSCP.append(packet.ipv6.tclass_dscp)
            
        else:
            vedere.append(packet)
        '''

#Totale = [['Label DSCP', 'ttl', 'Protocol', 'header len', 'length'],
#            ['0', 124, 6, 20, 246],
#            ['0', 60, 1, 20, 32] ]


#DataFrame using the list of lists created before
tot_dat = pd.DataFrame(totale[1:],columns=totale[0])

#Type of features
categorical_features = ["Protocol"]
continuous_features = ["ttl","length"]


#Summary of the continuous feature
tot_dat[continuous_features].describe()
#Normalize

mms = MinMaxScaler()
mms.fit(tot_dat[continuous_features])
data_transformed = mms.transform(tot_dat[continuous_features])
data_transformed = pd.DataFrame(data_transformed, columns=["ttl","length"])

data_transformed["Protocol"] = tot_dat["Protocol"]

data_transformed.head()
#Convert dummy variables

#Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
#           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).

for col in categorical_features:
    dummies = pd.get_dummies(data_transformed[col], prefix=col)
    data_transformed = pd.concat([data_transformed, dummies], axis=1)
    data_transformed.drop(col, axis=1, inplace=True)

data_transformed.head()
data_transformed.columns

train = np.array(data_transformed)

x = data_transformed["ttl"]
y = data_transformed["length"]

plt.scatter( y, x)
plt.show() 

#Evaluating the optimal values of k for the algorithm K-means
Sum_of_squared_distances = []
K = range(1,15)
for k in K:
    km = KMeans(n_clusters=k)
    km = km.fit(train)
    Sum_of_squared_distances.append(km.inertia_)
    

#Plotting the result according to the Inertia
plt.plot(K, Sum_of_squared_distances, 'bx-')
plt.xlabel('k')
plt.ylabel('Sum_of_squared_distances')
plt.title('Elbow Method For Optimal k')
plt.show()


km = KMeans(n_clusters=3)
km = km.fit(train)

Counter(km.labels_)






from mpl_toolkits.mplot3d import Axes3D


colori = ["b", "r", "gold", "pink"]
colour = [colori[label] for label in list(km.labels_)]

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

x = data_transformed["ttl"]
y = data_transformed["length"]
#z = tot_dat['header len']
ax.scatter(x, y, c = colour)

ax.set_xlabel('ttl')
ax.set_ylabel('length')
#ax.set_zlabel('header Label')

plt.show()

'''
plt.scatter(x, y)
plt.show() 
'''
#Plot the result of the k-means
plt.scatter( x, y, c = colour)
plt.xlabel("ttl")
plt.ylabel("length")
plt.show()

colori = ["aliceblue", "gold", "r", "pink", "b", "khaki", "green", "violet", "plum"]

new_cl = []
alfa = []
for lab in list(tot_dat["Label DSCP"]):
    if lab == "0":
        new_cl.append(colori[0])
        alfa.append(0.2)
    elif lab == "8" or lab == "10" or lab == "12" or lab == "14":
        new_cl.append(colori[1])
        alfa.append(0.8)
    elif lab == "16" or lab == "18" or lab == "20" or lab == "22":
        new_cl.append(colori[2])
        alfa.append(0.8)
    elif lab == "24" or lab == "26" or lab == "28" or lab == "30":
        new_cl.append(colori[3])
        alfa.append(0.8)
    elif lab == "32" or lab == "34" or lab == "36" or lab == "38":
        new_cl.append(colori[4])
        alfa.append(0.8)
    elif lab == "40" or lab == "46" :
        new_cl.append(colori[5])
        alfa.append(0.8)
    elif lab == "48" :
        new_cl.append(colori[6])
        alfa.append(0.8)
    elif lab == "56" :
        new_cl.append(colori[7])
        alfa.append(0.8)
    else:
        print("Valore Strano", lab)
        new_cl.append(colori[8])
        alfa.append(0.8)
        
scalar = [0.5 if elem == "aliceblue" else 200 for elem in new_cl]

plt.scatter( x, y, c = new_cl , s = scalar, alpha = 0.3)
#plt.scatter( x, y, c = new_cl , alpha = 0.3)
plt.xlabel("ttl")
plt.ylabel("length")
plt.show()


############### PCA ##############

from sklearn import preprocessing
from sklearn.decomposition import PCA

#1)Center and scale data:

#scaled_data = preprocessing.scale(tot_dat[continuous_features])
scaled_data = preprocessing.scale(train)
pca = PCA()
pca.fit(scaled_data)
pca_data = pca.transform(scaled_data)

pre_var = np.round(pca.explained_variance_ratio_ * 100 , decimals = 1 ) 
labels = ["PC" + str(x) for x in range(1, len(pre_var)+1)]

plt.bar(x=range(1,len(pre_var)+1), height=pre_var, tick_label = labels)
plt.ylabel("Ciao")
plt.xlabel("Principal Component")
plt.title("Screen Plot")
plt.show()

pca_df = pd.DataFrame(pca_data, columns = labels)


plt.scatter(pca_df.PC1, pca_df.PC2)
plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
plt.title("My PCA Graph")

#for sample in pca_df.index:
#    plt.annotate(sample, (pca_df.PC1.loc[sample], pca_df.PC2.loc[sample]))

plt.show()


#New K-Means
train_2 = np.array(pca_df)

#Evaluating the optimal values of k for the algorithm K-means
Sum_of_squared_distances = []
K = range(1,15)
for k in K:
    km = KMeans(n_clusters=k)
    km = km.fit(train_2)
    Sum_of_squared_distances.append(km.inertia_)
    

#Plotting the result according to the Inertia
plt.plot(K, Sum_of_squared_distances, 'bx-')
plt.xlabel('k')
plt.ylabel('Sum_of_squared_distances')
plt.title('Elbow Method For Optimal k')
plt.show()

km = KMeans(n_clusters=3)
km = km.fit(train)

Counter(km.labels_)

colori = ["b", "r", "gold", "pink"]
colour = [colori[label] for label in list(km.labels_)]


plt.scatter( pca_df["PC1"], pca_df["PC2"], c = colour )

plt.show()



#New Idea##

from sklearn.cluster import DBSCAN

clustering = DBSCAN(eps=3, min_samples=2).fit(train)


