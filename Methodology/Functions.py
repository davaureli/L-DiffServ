# -*- coding: utf-8 -*-
"""
Created on Fri Apr 12 09:54:23 2019

@author: Davide
"""
###Libraries###

import glob
import pickle  
import pyshark
import pyasn
import os

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import math
from collections import Counter

#from sklearn import preprocessing
#from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA
from sklearn.preprocessing import MinMaxScaler
from mpl_toolkits.mplot3d import Axes3D

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

#Plot the confusion Matrix
from sklearn.utils.multiclass import unique_labels
from matplotlib.colors import ListedColormap

#Cleaning Dataset through Under and Over sampling
from imblearn.combine import SMOTEENN
from imblearn.under_sampling import EditedNearestNeighbours
from imblearn.under_sampling import RepeatedEditedNearestNeighbours

#Classification Libraries
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

#K fold cross validation and Grid Search using the Pipeline
from imblearn.pipeline import make_pipeline
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import GridSearchCV

#Evaluation metrics
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score
from sklearn.metrics import make_scorer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


import warnings
warnings.filterwarnings("ignore")


#Data about the mapping between ASN and Ip addressees updated to 2019/March
asndb = pyasn.pyasn("IpAsn2019.dat")


dscp_tab = {0: "best effort",
            8: "Priority",
            10: "Priority",
            12: "Priority",
            14: "Priority",
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

## 0 - Creation of the Folder for each pcap

## 1 - Reading packets in a pcap file extracting info about the packets

def extract_Info_pckt(file_name):
    
    pcap = pyshark.FileCapture(file_name)

    tt = ["Label DSCP", "header len", "ds_field","ds_field_ecn", "length", "Protocol" ,"flag_df",
          "flag_mf", "flag_rb", "fragment_offset", "ttl", "IP_SRC", "IP_DST","src_port",
          "dst_port"] 
    
    totale = []
    print("Now I'm working on: " + file_name)
    print()
    
    #VM
    #title = (file_name.split("/")[-1].split(".")[-2])
    #Local
    title = (file_name.split("/")[-1].split(".")[0])[12:]
    
    print("This is title : " + title)
    
    
    i = 0
    dscp = []
    totale.append(tt)
    
    for packet in pcap:
        
        ### MAC Address verification ###
        sorgente = pcap[0].eth.src
            
        #Creating an empty list where we collect info about the packet
        #Useful this format to create then a DataFrame
        
        valori = []
        
        #print(packet.layers)
        #We extract onòy the packets from IP Level and only Version IPv4
        if 'IP' in packet and packet.eth.src == sorgente:
            
            
            #Label
            valori.append(packet.ip.dsfield_dscp)
            dscp.append(packet.ip.dsfield_dscp)
            #Features
            
            #Header Length
            valori.append(int(packet.ip.hdr_len))
            #Differentiated Service
            valori.append(int(packet.ip.dsfield,16))
            #Explicit Congestion Notification
            valori.append(packet.ip.dsfield_ecn)
            #Length of the Packet including the header
            valori.append(int(packet.ip.len))
            #Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
            valori.append(int(packet.ip.proto))
            #Flag Do not Fragment 
            valori.append(packet.ip.flags_df)
            #Flag More Fragment
            valori.append(packet.ip.flags_mf)
            #Flag Reserved - Must be 0
            valori.append(packet.ip.flags_rb)
            #Fragment Offset
            valori.append(packet.ip.frag_offset)
            #Time To Live
            valori.append(int(packet.ip.ttl))
            
            #sorgente = asndb.lookup(packet.ip.src)[0]
            #destinazione = asndb.lookup(packet.ip.dst)[0]
            
            #### IP Extraction ####
            #Here we extract the block related to the Anonymized Ip
            source = asndb.lookup(packet.ip.src)[1]
            destination = asndb.lookup(packet.ip.dst)[1]

            if  source:
                valori.append(source)
            else:
                #-1 for the undefined source as None, we are not able to join 
                #the IP Anonymized which belong to the same Network in the 
                #same Block Ip
                valori.append(-1)
                
            if  destination:
                #-1,Same statement for the destination 
                valori.append(destination)
            else:
                valori.append(-1)
               
            #### Extraction of the Port ####
            if "UDP" in packet:
                valori.append(packet.udp.srcport)
                valori.append(packet.udp.dstport)

            elif "TCP" in packet :
                valori.append(packet.tcp.srcport)
                valori.append(packet.tcp.dstport)            
                
            else:
                #Protocol as IP and ICMP e Ws.Short avranno come porta -1
                #Appendere 2 volte il valore -1
                valori.append(-1)
                valori.append(-1)
             
            #Update the number of pckts
            i += 1
            
            #Store all the caracteristics of a packet into the Totale list
            totale.append(valori)
         
    print("Now we have finished the analysis so we closed the file: " + file_name)     
    pcap.close()
    print(len(totale))
    #Creation of the data frame
    tot_dat = pd.DataFrame(totale[1:],columns = totale[0])
    
    #We are saving the dataframe of Features Packets
    with open('FeaturesDataFrame/' + title + '.pkl', 'wb') as f:
        pickle.dump(tot_dat, f)
        
    print("I'm saving on the Folder shareCluster")
    
    #Save in a share folder for making then the clustering part
    with open('../shareCluster/' + title + '.pkl', 'wb') as f:
        pickle.dump(tot_dat, f)
        
    print("Saved into shareCluster")
    
    print()
    print("Here we have analyzed this number of pckts: " + str(i))
    print()
    print("Occurrences dict creation")
    print()
    
    #Create a dictionary for the number of occurrences od dscp label
    occ = dict(Counter(dscp))
    print(occ)
    print()    
    # Store data 
    with open('OccurrencesDetailed/' + title + '.pkl', 'wb') as f:
        pickle.dump(occ, f, protocol=pickle.HIGHEST_PROTOCOL)
    print("Finish storage for this file")
    print()


def packetAnalysis():
    
    diz_label_dscp = {}
    totale = 0
    
    for file in glob.glob("./OccurrencesDetailed/*.pkl"):
        print("Working with this file: " + str(file))
        print()
        with open( file, 'rb') as f:
            occ = pickle.load(f)
        occ = {int(k):v for k,v in occ.items()}
        print()
        print(occ)
        print()
        totale += sum(occ.values())
        #Taking all possible DSCP
        for val in occ:
            
            #We need to use integer values because the label is a string but the DSCP table is
            #written using integer values

            #If is a Known DSCP
            if val in dscp_tab:
                if dscp_tab[val] not in diz_label_dscp:
                    diz_label_dscp[dscp_tab[val]] = occ[val]
                else:
                    diz_label_dscp[dscp_tab[val]] += occ[val]
            #If it is an Unknown DSCP
            else:
                diz_label_dscp[val] = occ[val]
    #Now we have a dictionary with key string if it is a Known DSCP otherwise
    #we mantain an integer value as DSCP key. In totale is stored the total number of packets with DSCP label
    return diz_label_dscp, totale


def Statistics(dictionary, total_packet):
    
    percentage = {}
    non_dscp = 0
        
    for type_dscp in dictionary:
        if type(type_dscp) == str:
            percentage[type_dscp] = round(dictionary[type_dscp],4)
        else:
            print(type_dscp)
            non_dscp += dictionary[type_dscp]
    percentage["Not Known"] = round(non_dscp,4)
    
    print(percentage)

    
    ### Bar Chart all DSCP ###

    plt.rcdefaults()
    labels = list(percentage.keys())

    #Stiamo creando le liste dove mettiamo le percentuali per classe
    sizes = [ round(percentage[elem]*100/sum(percentage.values()),4)  for elem in labels]
    
    with open("lista_secci_paper.pkl", "wb") as fp:   #Pickling
        pickle.dump(sizes, fp)
    
    print()
    print("PERCENTUALI !!!!!")
    print()
    print()
    print(sizes)
    print()
    print()
    sizes = [ percentage[elem]  for elem in labels]
    #legend = [labels[i]+ " (" + str(round(sizes[i],2)) + "%)" for i in range(len(labels))]
    #legend = [labels[i] for i in range(len(labels))]
    legend = ["Best Effort","Immediate","Flash Voice","Internetwork Control","Critical Voice RTP","Priority","Network Control","Not Known"]
    y_pos = np.arange(len(labels))
    # Example data
    #people = labels
    #y_pos = np.arange(len(people))
    #performance = sizes
    #error = np.random.rand(len(people))
    colors = ["plum",'#ff9999','#66b3ff','#99ff99','#ffcc99', '#3182bd', '#6baed6', '#fd8d3c','#66b3ff']
    h = plt.barh(y_pos, sizes, align='center', label=labels, color=colors)
    plt.yticks(y_pos, labels)
    #plt.xlabel('% of Occurrences')
    plt.title('DSCP Distribution', fontsize = 'medium')
    #plt.grid(True)
    plt.legend(h,legend, loc= "upper right")
    plt.tight_layout()
    #Scale percentages
    plt.xscale("log")
    plt.savefig("Images_Distribution/Distribution DSCP.png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()
    print("Saved the first picture DSCP")


    ###Bar Chart about not Known DSCP beginning #####
    
    different_NotKnown_dscp = {str(k):dictionary[k] for k in dictionary if type(k) == int}


    plt.rcdefaults()
    labels = list(different_NotKnown_dscp.keys())
    
    sizes = [ round(different_NotKnown_dscp[elem]*100/sum(list(different_NotKnown_dscp.values())),4) for elem in labels]
    legend = [labels[i]+ " (" + str(round(sizes[i],2)) + "%)" for i in range(len(labels))]
    
    y_pos = np.arange(len(labels))
    # Example data
    #people = labels
    #y_pos = np.arange(len(people))
    #performance = sizes
    #error = np.random.rand(len(people))
    colors = ["plum",'#ff9999','#66b3ff','#99ff99','#ffcc99', '#3182bd', '#6baed6', '#fd8d3c']
    h = plt.barh(y_pos, sizes, align='center', label=labels, color=colors)
    plt.yticks(y_pos, labels)
    plt.xlabel('% of Occurrences')
    plt.title('DSCP Distribution of NotKnown Classes', fontsize = 'medium')
    #plt.grid(True)
    plt.legend(h,legend, loc= "upper right", fontsize = "small")
    plt.tight_layout()
    plt.savefig("Images_Distribution/NotKnown.png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()
    print("Saved the second picture DSCP")
    
    #### Bar Chart without Best Effort and not Known DSCP #####
    
    percentage_mod  = {key : percentage[key] for key in percentage.keys() if key != 'best effort' and key != 'Not Known' }
    print(percentage_mod)
    plt.rcdefaults()
    labels = list(percentage_mod.keys())
    
    sizes = [ round(percentage_mod[elem]*100/sum(list(percentage_mod.values())),2) for elem in labels]
    print(sizes)
    legend = [labels[i]+ " ( " + str(sizes[i]) + "%)" for i in range(len(labels))]
    
    y_pos = np.arange(len(labels))
    print(y_pos)
    # Example data
    #people = labels
    #y_pos = np.arange(len(people))
    #performance = sizes
    #error = np.random.rand(len(people))
    colori_possible = ['#ff9999','#66b3ff','#99ff99','#ffcc99', '#3182bd', '#6baed6', '#fd8d3c']
    colors = [ colori_possible[i] for i in range(len(sizes))]
    h = plt.barh(y_pos, sizes, align='center', label=labels, color=colors)
    plt.yticks(y_pos, labels)
    plt.xlabel('% of Occurrences')
    plt.title('DSCP Distribution without BE and NotKnown', fontsize = 'medium')
    plt.legend(h,legend,loc= "upper right")
    plt.tight_layout()
    plt.savefig("Images_Distribution/Distribution DSCP without BE and NotKnown.png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()
    print("Saved the third picture DSCP")
    


def Ip_and_Port_Selection(dataframe,label, title):
    
    #We are excluding from the variables "dsfield" because it synthesizes the DSCP field and
    #ECN field. It is not useful to include in the classification problems
    
    variables = [ i for i in dataframe.columns if i != 'ds_field']
    print("We start considering these variables: ")
    print(variables)
    
    #Transform into numeric the caracteristics collect as strings but the could be considered
    #as numeric to draw the CORRELATION plot
    
    #first_clean['Label DSCP'] = pd.to_numeric(tot_dat['Label DSCP'])
    dataframe['flag_df'] = pd.to_numeric(dataframe['flag_df'])
    dataframe['flag_mf'] = pd.to_numeric(dataframe['flag_mf'])
    
    
    #Now we are excluding the variables with a std equal to 0 so the dictionary created by Counter
    #will have only one element so 1 key.    
    
    mantain_col = []
    for col in variables:
        diz = Counter(dataframe[col])
        if len(diz) > 1:
            mantain_col.append(col)      
    
    #Now we have concluded the first kind of cleaning
    first_clean =  dataframe[mantain_col].copy() 

    
    #Variables considered numeric for our corr plot, we not included the Label DSCP 

    numeric = ["length", "flag_df", "flag_mf", "ttl"]
    
    numeric = [ va for va in first_clean.columns if va in numeric]
    
    data = first_clean[numeric]
    
    corr = data.corr()
    fig = plt.figure()
    ax = fig.add_subplot(111)
    cax = ax.matshow(corr,cmap='coolwarm', vmin=-1, vmax=1)
    fig.colorbar(cax)
    ticks = np.arange(0,len(data.columns),1)
    ax.set_xticks(ticks)
    plt.xticks(rotation=90)
    ax.set_yticks(ticks)
    ax.set_xticklabels(data.columns)
    ax.set_yticklabels(data.columns)
    
    #for VM
    #plt.savefig("./Images_Distribution/CorrelationPlot.png", dpi = 150, figsize=(12,6))
    #for LOCAL
    plt.savefig("./Images_Distribution/"+ title +".png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()
    
    print("Saved the Correlation Plot")
    
    ### IP Part ###

    ## Remove all the packets with an unknown AS, IP signed as -1
    first_clean = first_clean.drop(first_clean[first_clean["IP_SRC"] == -1].index)
    first_clean = first_clean.drop(first_clean[first_clean["IP_DST"] == -1].index)
    
    ### IP Source ### ---> We have to select the number that mantain the max Info 
    a = Counter(first_clean["IP_SRC"])
    for i in range(1, len(a.most_common())):
        a_buoni = a.most_common(i)
        X = [elem[1] for elem in a_buoni]
        
        par_tot = sum(X)
        tot = sum(list(a.values()))
        percent = par_tot*100 / tot
        
        if percent >= 85:
            break
    print("The number of element selected for IP_Src are: " + str(i))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
    
    Ip_src_togliere =[elem[0] for elem in a.most_common() if elem not in a_buoni ] 
    
    
    ### IP Destination ### ---> Abbiamo mantenuto l' 85% dell'informazione
    r = Counter(first_clean["IP_DST"])
    
    for j in range(1, len(r.most_common())):
        r_buoni = r.most_common(j)
        Y = [elem[1] for elem in a_buoni]
        
        par_tot = sum(Y)
        tot = sum(list(r.values()))
        percent = par_tot*100 / tot
        
        if percent >= 85:
            break
    print("The number of element selected for IP_Dst are: " + str(j))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
    
    Ip_dst_togliere =[elem[0] for elem in r.most_common() if elem not in r_buoni] 
                      
    print()
    
    print("Removing the IP from SRC and DST ")
    
    first_clean["IP_SRC"] = first_clean["IP_SRC"].replace(Ip_src_togliere, -1)
    first_clean["IP_DST"] = first_clean["IP_DST"].replace(Ip_dst_togliere, -1)
    print(first_clean.head())
    print(type(first_clean))
    ### We can now remove the observations with IP in SRC or DST equals to -1
    ### and then we can go on
    
    
    #first_clean = first_clean.loc[(first_clean["IP_SRC"] != -1) & (first_clean["IP_DST"] != -1)]
    
    print(first_clean.head())
    print()
    print("Now we can go on working with PORT_Number")
    
    
    #### PORT Part####
    
    ## We 'll select the Port number, in src or dst most important with the highest value
    ## of occurrences
    
    ##First of all we have to join the occurrences of Port SRC and Port Dst
    
    ##Source Port##
    a = Counter(first_clean["src_port"])

    '''
    X = [elem[1] for elem in a.most_common(70)]
    par_tot = sum(X)
    tot = sum(list(a.values()))
    
    par_tot*100 / tot
    '''
    ##Destination Port##
    r = Counter(first_clean["dst_port"])
    '''
    Y = [elem[1] for elem in r.most_common(120)]
    par_tot = sum(Y)
    tot = sum(list(r.values()))
    
    par_tot*100 / tot
    '''
    
    Port_Fondamental = []
    for i in range(first_clean.shape[0]):
        ss = first_clean.iloc[[i]]["src_port"].values[0]
        dd = first_clean.iloc[[i]]["dst_port"].values[0]
        
        if a[ss] >= r[dd]:
            Port_Fondamental.append(ss)
        else:
            Port_Fondamental.append(dd)
        
    first_clean["Port Important"] = Port_Fondamental    
    
    print()
    print("The most important ports are : ")
    print(set(Port_Fondamental))

    v = Counter(first_clean["Port Important"])
    
    for h in range(1, len(v.most_common())):
        v_buoni = v.most_common(h)
        W = [elem[1] for elem in v_buoni]
    
        par_tot = sum(W)
        tot = sum(list(v.values()))
        percent = par_tot*100 / tot
    
        if percent >= 95:
            break
    print("The number of element selected for the PORTS_Number are: " + str(h))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
    
    
    port_delete =[elem[0] for elem in v.most_common() if elem not in v_buoni ]     
    
    ##Final dataset
    
    ##In this way we maintain the label brfore the cleaning part
    
    if label == "best effort":
        lab = [ "0" for i in range(first_clean.shape[0])]
        first_clean["Label DSCP"] = lab
    
    elif label == "Non best effort" :
        lab = [ "1" for i in range(first_clean.shape[0])]
        first_clean["Label DSCP"] = lab
    
    #variabili = ['Label DSCP', 'ds_field_ecn', 'length', 'Protocol', 'flag_df',
           #'flag_mf', 'fragment_offset', 'ttl', 'IP_SRC', 'IP_DST', 'Port Important']
    
    #final_data = data_clean[variabili].copy()
    
    #The value 0 means that the Port with few occurrences are replaced by zero value
    first_clean["Port Important"] = first_clean["Port Important"].replace(port_delete, 0)
    
    # -1 --> Protocol which does not use any port
    #  0 --> Protocol uses a port, but its occurrences are really few 
    
    #Retrieve the label DSCP
    cols = first_clean.columns.tolist()
    cols.insert(0, cols.pop(cols.index('Label DSCP')))
    first_clean = first_clean.reindex(columns= cols)
    
    return first_clean
    
def cleaning_Data():


    files = glob.glob('./FeaturesDataFrame/*pkl')
    print(files)
    df_new = pd.concat([pd.read_pickle(fp) for fp in files], ignore_index=True)
    print(df_new.head())
    print("NOW START TO CLEAN THE BEST EFFORT DATAFRAME")
    print()
    #Extract only Best Effort
    df_BE = df_new[df_new["Label DSCP"] == "0"].copy()
    
    df_BE = Ip_and_Port_Selection(df_BE,"best effort", "Correlation Best Effort")
    
    print("NOW START TO CLEAN THE NON BEST EFFORT DATAFRAME")
    print()
    #Extract only Non Best Effort
    df_Non_BE = df_new[df_new["Label DSCP"] != "0"].copy()
    
    df_Non_BE = Ip_and_Port_Selection(df_Non_BE,"Non best effort", "Correlation Non Best Effort")
    print("We have finished to CLEAAAAN !!!!")
    
    df_final  = pd.concat([df_BE, df_Non_BE], ignore_index=True)
    return df_final
    
    
def PCA_decomposition(dataframe, 
        #categorical_features = ["ds_field_ecn", "Protocol", "flag_df","IP_SRC", "IP_DST","Port Important"],
        categorical_features = ["ds_field_ecn", "Protocol", "flag_df","Port Important"],
        continuous_features = ["length", "ttl"],
        n_comp = 3):
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella PCA 
    
    label = dataframe["Label DSCP"]
    
    print("These are the variables selected:")
    print()
    print("For the CATEGORICAL we have: " )
    print(categorical_features)
    print()
    print("For the CONTINUOUS we have: ")
    print(continuous_features)
    print()
    print()
    
    #Summary of the continuous feature
    print("This is a summary for the continuos Features")
    dataframe[continuous_features].describe()
    
    #Normalize the Continuous variables
    
    mms = MinMaxScaler()
    mms.fit(dataframe[continuous_features])
    data_transformed = mms.transform(dataframe[continuous_features])
    
    #Creation of a new DataFrame
    data_transformed = pd.DataFrame(data_transformed, columns= continuous_features)
    
    
    #Drop the index to concatenate in a correct way the 2 dataframes
    dataframe = dataframe.reset_index(drop = True) 
    
    #Add the categorical features to the new data frame normalized
    data_transformed[categorical_features] = dataframe[categorical_features]
    
    print()
    print("This is the new DataFrame: ")
    print(data_transformed.head())
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    print("QUIIIIII")
    print()
    print(data_transformed.head())
    print()
    
    for col in categorical_features:
        #Inserito il drop first drop_first=True
        dummies = pd.get_dummies(data_transformed[col], prefix=col, drop_first=True )
        #dummies = pd.get_dummies(data_transformed[col], prefix=col)
        data_transformed = pd.concat([data_transformed, dummies], axis=1)
        data_transformed.drop(col, axis=1, inplace=True)
    print("QUIIIIII")
    print()
    print(data_transformed.head())
    print()
    data_transformed["Label DSCP"] = label
    print(Counter(data_transformed["Label DSCP"]))
    
    cols = data_transformed.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    data_transformed = data_transformed.reindex(columns= cols)
    
    #Taking the train dataset
    #train = np.array(data_transformed)
    
    pca = PCA(n_components = n_comp)
    pca.fit(data_transformed.iloc[:,1:])
    pca_data = pca.transform(data_transformed.iloc[:,1:])
    
    pre_var = np.round(pca.explained_variance_ratio_ * 100 , decimals = 1 )
    
    
    dd_r = "PCA"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
     
    labels = ["PC" + str(x) for x in range(1, len(pre_var)+1)]
    
    plt.bar(x=range(1,len(pre_var)+1), height=pre_var, tick_label = labels)
    plt.ylabel("Percentage of Explained Variance")
    plt.xlabel("Principal Component")
    plt.title("Screen Plot for Explained_Variance ")
    plt.savefig('./PCA/Explained_Variance.png')
    #plt.show()
    plt.close()
    
    pca_df = pd.DataFrame(pca_data, columns = labels)
    
    color = [] 
    for i in range(data_transformed.shape[0]):
        dscp  = list(data_transformed.iloc[[i]]["Label DSCP"].values)[0]
        if  dscp == "0":
            color.append("b")
        else:
            color.append("r")
        
    #plt.scatter(pca_df.PC1, pca_df.PC2, c = color)
    plt.scatter(pca_df.PC1, pca_df.PC2, c = color)
    plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
    plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
    plt.title("My PCA Graph")
    plt.savefig('./PCA/PCA_GRAPH.png')
    plt.show()
    #plt.close()
    
    #See how much each variable influence or impact in the variable
    
    print(data_transformed.columns)
    
    print()
    print()
    ##PCA1
    loading_scores = pd.Series(pca.components_[0], index = data_transformed.iloc[:,1:].columns )
    sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
    top_val = sorted_loadng_scores[0:10].index.values
    print(loading_scores[top_val])
    print()
    print()
    loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC1.csv')
    
    ##PCA2
    
    print()
    print()
    loading_scores = pd.Series(pca.components_[1], index = data_transformed.iloc[:,1:].columns )
    sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
    top_val = sorted_loadng_scores[0:10].index.values
    print(loading_scores[top_val])
    print()
    print()
    loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC2.csv')
    
    ##PCA3

    print()
    print()
    loading_scores = pd.Series(pca.components_[2], index = data_transformed.iloc[:,1:].columns )
    sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
    top_val = sorted_loadng_scores[0:10].index.values
    print(loading_scores[top_val])
    print()
    print()
    loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC3.csv')
    
    ############# PLOT PCA 3D ############
    
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    
    x = pca_df.PC1
    y = pca_df.PC2
    z = pca_df.PC3
    #z = tot_dat['header len']
    ax.scatter(x, y, z, c = color)
    
    ax.set_xlabel("PC1 - {0}%" .format(pre_var[0]))
    ax.set_ylabel("PC2 - {0}%" .format(pre_var[1]))
    ax.set_zlabel("PC3 - {0}%" .format(pre_var[2]))
    plt.title("PCA Results in 3D")
    plt.savefig("./PCA/PCA Results in 3D.png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()

    pca_df["Label DSCP"] = label
    cols = pca_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    pca_df = pca_df.reindex(columns= cols)
    
    
    return pca_df


#This Function: Classification, could be used if we want to see the result of the classification 
#with an unbalanced dataset.

def Classification(dataset):
    
    dd_r = "Classification_Unbalanced"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
        
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()
    #Now we have to change this path and enter in our new folder
    os.chdir('./Classification_Unbalanced/')
    print("This is the NEW  cwd:  " + os.getcwd())
    
    print()
    print(dataset.head())
    print()
    #We are dividing the Ind. Variable to The lable    
    
    X = dataset.iloc[:, 1:3].values
    y = dataset.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    # Feature Scaling
    
    #sc = StandardScaler()
    #X_train = sc.fit_transform(X_train)
    #X_test = sc.transform(X_test)
    
    
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", "Random Forest"]
    
    print()
    print("Possible algorithm about Classification Problem")
    print(Ml_Algo)
    
    
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
    # Fitting Logistic Regression to the Training set
        
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)

        if method == "Logistic" :
        
            from sklearn.linear_model import LogisticRegression
            classifier = LogisticRegression(random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "SVM con Kernel":
            
            # Fitting Kernel SVM to the Training set
            from sklearn.svm import SVC
            classifier = SVC(kernel = 'rbf', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Naive Bayes":
            # Fitting Naive Bayes to the Training set
            from sklearn.naive_bayes import GaussianNB
            classifier = GaussianNB()
            classifier.fit(X_train, y_train)
        
        elif method == "Decision Trees":
            # Fitting Decision Tree Classification to the Training set
            from sklearn.tree import DecisionTreeClassifier
            classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Random Forest":
            # Fitting Random Forest Classification to the Training set
            from sklearn.ensemble import RandomForestClassifier
            classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 0)
            classifier.fit(X_train, y_train)
        
        # Predicting the Test set results
        y_pred = classifier.predict(X_test)
        
        # Making the Confusion Matrix

        
        cm = confusion_matrix(y_test, y_pred)
        
        # Making the Confusion Matrix
        
        print()
        print("We obtained this result, Confusion Matrix: ")
        print(cm)
        print()
        
# =============================================================================
#       PLOT CONFUSION MATRIX
# =============================================================================
        print("Plot the confusion Matrix")
        
        fig, ax = plt.subplots()
        cmap=plt.cm.Blues
        im = ax.imshow(cm, interpolation='nearest', cmap=cmap)
        ax.figure.colorbar(im, ax=ax)
        # We want to show all ticks...
        ax.set(xticks=np.arange(cm.shape[1]),
               yticks=np.arange(cm.shape[0]),
               # ... and label them with the respective list entries
               xticklabels=["Best Effort", "Non BE"], 
               yticklabels=["Best Effort", "Non BE"],
               title='Confusion matrix with ' + method ,
               ylabel='True label',
               xlabel='Predicted label')
    
        # Rotate the tick labels and set their alignment.
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                 rotation_mode="anchor")
        # Loop over data dimensions and create text annotations.
        fmt = '.0f'
        thresh = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, format(cm[i, j], fmt), ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        fig.tight_layout()
        plt.savefig("./" + nn_dir + "/ConfusionMatrix_using_" + method + ".png")
        #plt.show()
        plt.close()
         
        print()
        np.save("./" + nn_dir + "/ConfusionMatrix_using_" + method, cm)
        
        accuracy = accuracy_score(y_test, y_pred)
        print("This is the Accuracy score: " + str(round(accuracy,2)*100) + "%")
        print()
        
        #precision = precision_score(y_test, y_pred)
        #print("The precision is: " + str(precision))
        
        #recall = recall_score(y_test, y_pred)
        #print("This is the recall score: " + str(recall))
        
        # Visualising the TRAINING set results
        
        X_set, y_set = X_train, y_train
        
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
 
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, cmap = ListedColormap(('red', 'green')))
        
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = ListedColormap(('red', 'green'))(i), label = j)
        plt.title('Classifier (Training set) using: ' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of training with " + method + ".png", dpi = 150, figsize=(12,6))
        plt.show()
        plt.close()
        
        # Visualising the TEST set results
        
        X_set, y_set = X_test, y_test
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, cmap = ListedColormap(('red', 'green')))
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = ListedColormap(('red', 'green'))(i), label = j)
        plt.title('Classifier (Test set) using' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of test with " + method + ".png", dpi = 150, figsize=(12,6))
        plt.show()
        plt.close()
        
#Respect to the previous one, now we are oversampling the dataset
        
def Oversampling(dataset):
    
    #dd_r = "Oversampling"
    
    #try:  
        #os.mkdir(dd_r)
    #except OSError:  
        #print ("Creation of the directory %s failed" % dd_r)
    #else:  
        #print ("Successfully created the directory %s " % dd_r)
        
    #print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    #print()
    #Now we have to change this path and enter in our new folder
    #os.chdir('./Oversampling/')
    #print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Oversampling !!!!")
    print()
    print(dataset.head())
    print()
    #We are dividing the Ind. Variable to The lable    
    
    #X = dataset.iloc[:, 1:].values
    #y = dataset.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    categorical_features = ["ds_field_ecn", "Protocol", "flag_df","IP_SRC", "IP_DST","Port Important"]
    continuous_features = ["length", "ttl"]
    
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella PCA 
    
    #label = dataframe["Label DSCP"]
    
    #row = X_train.shape[0]
    #y_train = np.reshape(y_train,(row,1))

    #data = np.concatenate((y_train, X_train ), axis=1)
    #col = dataset.columns

    #df = pd.DataFrame(data = data, columns = col)
    
    print("These are the variables selected:")
    print()
    print("For the CATEGORICAL we have: " )
    print(categorical_features)
    print()
    print("For the CONTINUOUS we have: ")
    print(continuous_features)
    print()
    print()
    
    print()
    print(dataset.head())
    print()
    #Summary of the continuous feature
    print("This is a summary for the continuos Features")
    #X_train[continuous_features].describe()
    
    #Normalize the Continuous variables
    
    mms = MinMaxScaler()
    mms.fit(dataset[continuous_features])
    data_transformed = mms.transform(dataset[continuous_features])
    
    #Creation of a new DataFrame
    data_transformed = pd.DataFrame(data_transformed, columns= continuous_features)
    
    
    #Drop the index to concatenate in a correct way the 2 dataframes
    dataset = dataset.reset_index(drop = True) 
    
    #Add the categorical features to the new data frame normalized
    data_transformed[categorical_features] = dataset[categorical_features]
    
    print()
    print("This is the new DataFrame: ")
    print(data_transformed.head())
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    
    for col in categorical_features:
        dummies = pd.get_dummies(data_transformed[col], prefix=col)
        data_transformed = pd.concat([data_transformed, dummies], axis=1)
        data_transformed.drop(col, axis=1, inplace=True)
    
    print(data_transformed.head())
    data_transformed["Label DSCP"] = dataset["Label DSCP"]
    print(Counter(data_transformed["Label DSCP"]))
    
    cols = data_transformed.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    data_transformed = data_transformed.reindex(columns= cols)
    
    print("Coluuuuuuums: ")
    print(data_transformed.columns)
    print()
    #tale modifica deve esser effettuata nel codice del clustering dove
    #prendiamo i file pkl di tutti i pcap analizzati !! 
    #Trasportare tale idea nel codice del clustering
    return data_transformed





def Oversampling_and_PCA(dataset):
    
    dd_r = "Oversampling_and_PCA"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
        
    
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Oversampling !!!!")
    print()
    print(dataset.head())
    print()
    
    #We are dividing the Ind. Variable to The lable    
    
    #X = dataset.iloc[:, 1:].values
    #y = dataset.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    #categorical_features = ["ds_field_ecn", "Protocol", "flag_df","IP_SRC", "IP_DST","Port Important"]
    categorical_features = ["ds_field_ecn", "Protocol", "flag_df","Port Important"]
    continuous_features = ["length", "ttl"]
    
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella PCA 
    
    #label = dataframe["Label DSCP"]
    
    #row = X_train.shape[0]
    #y_train = np.reshape(y_train,(row,1))

    #data = np.concatenate((y_train, X_train ), axis=1)
    #col = dataset.columns

    #df = pd.DataFrame(data = data, columns = col)
    
    print("These are the variables selected:")
    print()
    print("For the CATEGORICAL we have: " )
    print(categorical_features)
    print()
    print("For the CONTINUOUS we have: ")
    print(continuous_features)
    print()
    print()
    
    print()
    print(dataset.head())
    print()
    #Summary of the continuous feature
    print("This is a summary for the continuos Features")
    #X_train[continuous_features].describe()
    
    #Normalize the Continuous variables
    
    mms = MinMaxScaler()
    mms.fit(dataset[continuous_features])
    data_transformed = mms.transform(dataset[continuous_features])
    
    #Creation of a new DataFrame
    data_transformed = pd.DataFrame(data_transformed, columns= continuous_features)
    
    
    #Drop the index to concatenate in a correct way the 2 dataframes
    dataset = dataset.reset_index(drop = True) 
    
    #Add the categorical features to the new data frame normalized
    data_transformed[categorical_features] = dataset[categorical_features]
    
    print()
    print("This is the new DataFrame: ")
    print(data_transformed.head())
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    
    
    for col in categorical_features:
        #Inserito il drop first drop_first=True
        dummies = pd.get_dummies(data_transformed[col], prefix=col, drop_first=True )
        #dummies = pd.get_dummies(data_transformed[col], prefix=col)
        data_transformed = pd.concat([data_transformed, dummies], axis=1)
        data_transformed.drop(col, axis=1, inplace=True)
       
    print(data_transformed.head())
    data_transformed["Label DSCP"] = dataset["Label DSCP"]
    print(Counter(data_transformed["Label DSCP"]))
    
    cols = data_transformed.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    
    #Salvare il dataframe dataTransformed, dopo eseguiremo cross validation su questo
    data_transformed = data_transformed.reindex(columns= cols)
    data_transformed.to_pickle("data_transformed_for_CrossValidation.pkl") 
    
    print(" Coluuuuuuums: ")
    print(data_transformed.columns)
    print()
    
    X = data_transformed.iloc[:, 1:].values
    y = data_transformed.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0, stratify = y)
    
    print("Singular Example - Distribution of y_test:")
    print(Counter(y_test))
    print()
    
    print("Try to BALANCE the DataSet")
    #Extract info data for X_train and y_train
    
    X_train = data_transformed.iloc[:, 1:].values
    y_train = data_transformed.iloc[:, 0].values
    
    print()
    print("Starting Point")
    print(sorted(Counter(y_train).items()))
    print()
    
    print("NOW START UNDERSAMPLING:")
    print()
    
    print("Using ENN")
    print()
    

    
    #Capire se è utile inserire il calcolo per il numero di vicini, o mettere una propria soglia !!!
    
    #print("Numero di vicini: " + str(int(math.log(len(X_train)))))
    #enn = EditedNearestNeighbours(random_state = 0,  n_neighbors = 20, n_jobs=2,)
    
    renn = RepeatedEditedNearestNeighbours(random_state = 0,  n_neighbors = 250, n_jobs= -1 , max_iter = 100)
    
    #Transform the occurrences of train X and y
    #X_under_resampled, y_under_resampled = enn.fit_resample(X_train, y_train)
    X_under_resampled, y_under_resampled = renn.fit_resample(X_train, y_train)
      
    print("After undersampling...")
    print(sorted(Counter(y_under_resampled).items()))
    print()
    
    print("NOW START OVERSAMPLING:")    
    print()
    print("Using SMOTEENN")
    
    print()
    print("Beginning Distribution: ")
    print(sorted(Counter(y_under_resampled).items()))
    
    #Making the SMOOTEENN
    smote_enn = SMOTEENN(random_state=0)
    
    #Resample about X and y
    X_resampled, y_resampled = smote_enn.fit_resample(X_under_resampled, y_under_resampled)
    
    print()
    print("Final Distribution after Undersampling & Oversampling: ")
    print(sorted(Counter(y_resampled).items()))
    
    
    #TRAIN DATA FRAME
    row = X_resampled.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_resampled = np.reshape(y_resampled,(row,1))

    data = np.concatenate((y_resampled, X_resampled), axis=1)
    print()
    print(data)
    
    #col = ["Label DSCP","PCA_1", "PCA_2"]
    
    col = data_transformed.columns
    
    df_balanced_train = pd.DataFrame(data = data, columns = col)
    
    #Dobbiamo trasformare le approssimazioni delle variabili non numeriche,
    #poiché gli esempi sintetici hanno come valore di protocollo un valore differente da
    # 0 o 1 ma un valore razionale(e.g. protocol_6 0,25), la nostra idea è di approssimare 
    #tali valori
    
    print("Cleaning the SMOOTEENN Result")
    
    colonne_cat = []
    for col in list(df_balanced_train.columns):
        if col != "Label DSCP" and col != "length" and col != "ttl":
            colonne_cat.append(col)
    print()
    print("Queste sono le colonne che dobbiamo arrotondare poich smoote crea esempi sintetici Non corretti")
    print(colonne_cat)
    print()
    
    df_balanced_train[colonne_cat] = np.round(df_balanced_train[colonne_cat].astype(np.double),0)
    
    
    for i in colonne_cat:
        print(Counter(df_balanced_train[i]))
    print()
    
    etichetta_test = [ "0" for i in range(df_balanced_train.shape[0])]
    
    
    idx = len(df_balanced_train.columns)
    df_balanced_train.insert(loc=idx, column='Etichetta Test', value= etichetta_test)
    
    print()
    print("Final Data Frame Head")
    print(df_balanced_train.head())
    
    #TEST DATA FRAME
    row = X_test.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_test = np.reshape(y_test,(row,1))

    data_test = np.concatenate((y_test, X_test), axis=1)
    print()
    print(data_test)
    #col = ["Label DSCP","PCA_1", "PCA_2"]
    
    col = data_transformed.columns
    
    df_balanced_test = pd.DataFrame(data = data_test, columns = col)
    
    etichetta_test = [ "1" for i in range(df_balanced_test.shape[0])]
    
    
    idx = len(df_balanced_test.columns)
    df_balanced_test.insert(loc=idx, column='Etichetta Test', value= etichetta_test)
    
    print(df_balanced_test.head())
    
    df_balanced = pd.concat([df_balanced_train, df_balanced_test])
    print()
    print("NUUUUUL Values ?? ")
    print(df_balanced.isnull().sum())

    print()
    print("Staaaaaaart PCA !!!")
    
    dd_r = "PCA"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
    
    print()
    #n_comp = 3
    n_comp = 2
    
    pca = PCA(n_components = n_comp)
    pca.fit(df_balanced.iloc[:,1:-1])
    pca_data = pca.transform(df_balanced.iloc[:,1:-1])
    
    pre_var = np.round(pca.explained_variance_ratio_ * 100 , decimals = 1)
    
    ##PCA1
    
    print("PCA_1")
    print()
    loading_scores = pd.Series(pca.components_[0], index = df_balanced.iloc[:,1:-1].columns )
    sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
    top_val = sorted_loadng_scores[0:10].index.values
    print(loading_scores[top_val])
    print()
    print()
    loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC1.csv')
    
    ##PCA2
    
    print("PCA_2")
    print()
    loading_scores = pd.Series(pca.components_[1], index = df_balanced.iloc[:,1:-1].columns )
    sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
    top_val = sorted_loadng_scores[0:10].index.values
    print(loading_scores[top_val])
    print()
    print()
    loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC2.csv')

    ##PCA3

# =============================================================================
#     print("PCA_3")
#     print()
#     loading_scores = pd.Series(pca.components_[2], index = df_balanced.iloc[:,1:-1].columns )
#     sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
#     top_val = sorted_loadng_scores[0:10].index.values
#     print(loading_scores[top_val])
#     print()
#     print()
#     loading_scores[top_val].to_csv('./PCA/Influenza_Variabili_PC3.csv')
# =============================================================================
    

    labels = ["PC" + str(x) for x in range(1, len(pre_var)+1)]
    
    print("Starting make the bar chart for the explained Variance")
    
    plt.bar(x=range(1,len(pre_var)+1), height=pre_var, tick_label = labels)
    plt.ylabel("Percentage of Explained Variance")
    plt.xlabel("Principal Component")
    plt.title("Screen Plot for Explained_Variance ")
    plt.savefig('./PCA/Explained_Variance.png')
    #plt.show()
    plt.close()
    
    print()
    print("Starting create the DataFrame for making the 2D plot !!!")
    
    pca_df = pd.DataFrame(pca_data, columns = labels)
    
    color = [] 
    for i in range(df_balanced.shape[0]):
        dscp  = list(df_balanced.iloc[[i]]["Label DSCP"].values)[0]
        if  dscp == "0":
            color.append("b")
        else:
            color.append("r")
            
    plt.scatter(pca_df.PC1, pca_df.PC2, c = color)
    plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
    plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
    plt.title("My PCA Graph")
    plt.savefig('./PCA/PCA_GRAPH.png')
    #plt.show()
    plt.close()
    
    
# =============================================================================
#     ############# PLOT PCA 3D ############
#     print()
#     print("Plot PCA 3D")
#     
#     fig = plt.figure()
#     ax = fig.add_subplot(111, projection='3d')
#     
#     x = pca_df.PC1
#     y = pca_df.PC2
#     z = pca_df.PC3
#     
#     ax.scatter(x, y, z, c = color)
#     
#     ax.set_xlabel("PC1 - {0}%" .format(pre_var[0]))
#     ax.set_ylabel("PC2 - {0}%" .format(pre_var[1]))
#     ax.set_zlabel("PC3 - {0}%" .format(pre_var[2]))
#     plt.title("PCA Results in 3D")
#     plt.savefig("./PCA/PCA Results in 3D.png", dpi = 150, figsize=(12,6))
#     #plt.show()
#     plt.close()
# =============================================================================
    
    print()
    print("We have finished the PCA Part")
    print()  
    
    # Here we attach the label variable to our DataFrame
    pca_df["Label DSCP"] = df_balanced["Label DSCP"].values
    cols = pca_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    pca_df = pca_df.reindex(columns= cols)
    
    # Then we attach even the label for dividing Train and Test
    pca_df["Etichetta Test"] = df_balanced["Etichetta Test"].values
    cols = pca_df.columns.tolist()
    cols.insert(len(cols), cols.pop(cols.index("Etichetta Test")))
    pca_df = pca_df.reindex(columns= cols)
    
    
    print("Completely recreate the DataFrame with col0 Label DSCP and col-1 Label Test, in the middle there are the variables")
    
    #CLASSIFICATION - SPLIT DATA FRAME
    
    print()
    print("Classification Time")
    
    #Splitting accoring to the last Label at position -1
    train = pca_df[pca_df['Etichetta Test'] == "0" ]
    test  = pca_df[pca_df['Etichetta Test'] == "1" ]  
    
    #Take the values so from a pd.DataFrame to np.array
    
    #Train
    X_train = train.iloc[:, 1:-1].values
    y_train = train.iloc[:, 0].values
    #Test
    X_test =  test.iloc[:, 1:-1].values
    y_test =  test.iloc[:, 0].values
    
    print()
    print("Possible algorithm about Classification Problem: ")
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", "Random Forest", "XGBoost"]
    print()
    print(Ml_Algo)
    
    #Interactive Part but for now we try with all the possibilities
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
        
        #Creation of a Directory for each possible Classification method 
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)

        if method == "Logistic" :
        
            
            classifier = LogisticRegression(random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "SVM con Kernel":
            
            # Fitting Kernel SVM to the Training set
            classifier = SVC(kernel = 'rbf', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Naive Bayes":
            
            # Fitting Naive Bayes to the Training set
            classifier = GaussianNB()
            classifier.fit(X_train, y_train)
        
        elif method == "Decision Trees":
            
            # Fitting Decision Tree Classification to the Training set
            classifier = DecisionTreeClassifier( random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Random Forest":
            # Fitting Random Forest Classification to the Training set
            
            classifier = RandomForestClassifier(random_state = 0)
            classifier.fit(X_train, y_train)
            
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0)
            classifier.fit(X_train, y_train)
        
        # Predicting the Test set results
        y_pred = classifier.predict(X_test)
        
        # Making the Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        
        print()
        print("We obtained this result, Confusion Matrix: ")
        print(cm)
        print()
        
# =============================================================================
#       PLOT CONFUSION MATRIX
# =============================================================================
        print("Plot the confusion Matrix")
        
        fig, ax = plt.subplots()
        cmap=plt.cm.Blues
        im = ax.imshow(cm, interpolation='nearest', cmap=cmap)
        ax.figure.colorbar(im, ax=ax)
        # We want to show all ticks...
        ax.set(xticks=np.arange(cm.shape[1]),
               yticks=np.arange(cm.shape[0]),
               # ... and label them with the respective list entries
               xticklabels=["Best Effort", "Non BE"], 
               yticklabels=["Best Effort", "Non BE"],
               title='Confusion matrix with ' + method ,
               ylabel='True label',
               xlabel='Predicted label')
    
        # Rotate the tick labels and set their alignment.
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                 rotation_mode="anchor")
        # Loop over data dimensions and create text annotations.
        fmt = '.0f'
        thresh = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, format(cm[i, j], fmt), ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        fig.tight_layout()
        plt.savefig("./" + nn_dir + "/ConfusionMatrix_using_" + method + ".png")
        #plt.show()
        plt.close()
         
        print()
        np.save("./" + nn_dir + "/ConfusionMatrix_using_" + method, cm)
        
        accuracy = accuracy_score(y_test, y_pred)
        print("This is the Accuracy score: " + str(round(accuracy,2)*100) + "%")
        print()
        
        report = classification_report(y_test, y_pred)
        print("This is the report")
        print(report)
        print()
        
        #precision = precision_score(y_test, y_pred)
        #print("The precision is: " + str(precision))
        
        #recall = recall_score(y_test, y_pred)
        #print("This is the recall score: " + str(recall))
      
        # Visualising the TRAINING set results
        
        X_set, y_set = X_train, y_train
        
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
 
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, cmap = ListedColormap(('red', 'green')))
        
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = ListedColormap(('red', 'green'))(i), label = j)
        plt.title('Classifier (Training set) using: ' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of training with " + method + ".png", dpi = 150, figsize=(12,6))
        #plt.show()
        plt.close()
        
        # Visualising the TEST set results
        
        X_set, y_set = X_test, y_test
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, cmap = ListedColormap(('red', 'green')))
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = ListedColormap(('red', 'green'))(i), label = j)
        plt.title('Classifier (Test set) using' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of test with " + method + ".png", dpi = 150, figsize=(12,6))
        #plt.show()
        plt.close()
        
        print("Finish the first attempt of classifciation")
        
        
############### VALIDATION Method #####################

def Validation():
    
    # Applying k-Fold Cross Validation using a Pipeline
    #L'idea sarà quella di riprendere il dataset iniziale, bilanciarlo attraverso Under e Oversampling
    #A quel punto suddividerlo in 10 cartelle e osservare i risultati che otteniamo di Accuracy
    #Ricordanto che le cartelle saranno stratificate ovvero manterranno la stessa percentuale di occorrenze tra 
    #Best e Non Best Effort
    print("Loading Dataset")
    #Dataframe[Label DSCP, Features] --> Structure
    data_frame = pd.read_pickle("data_transformed_for_CrossValidation.pkl")
    
    dd_r = "K-Fold Cross Validation"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
    print()
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Cross Validation !!!!")
    
    #Definition of the passages into the Pipeline
    
    #UNDERSAMPLING --> Repeated ENN
    renn = RepeatedEditedNearestNeighbours( random_state = 0, n_neighbors = 5, max_iter = 100, n_jobs= 4)
    
    #OVERSAMPLING --> SMOOTEENN
    smote_enn = SMOTEENN(random_state = 0)
     
    # Make the splits
    n = 12
    kf = StratifiedKFold(n_splits = n, random_state = 0)
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    print()
    print("Possible algorithm about Classification Problem: ")
    
    #We remove XGBoost for complexity
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", "Random Forest"]
    print(Ml_Algo)
    print()
    
    tot_acc={ j:[] for j in Ml_Algo}
    tot_F1={ j:[] for j in Ml_Algo}
    
    X = data_frame.iloc[:,1:].values
    y = data_frame.iloc[:,0].values
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
            
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)
    
    # Possible methods
    
        if method == "Logistic" :
            
            classifier = LogisticRegression(random_state = 0, n_jobs = 4)
            
        elif method == "SVM con Kernel":
            
            classifier = SVC(kernel = 'rbf', random_state = 0)
            
        elif method == "Naive Bayes":
            # Fitting Naive Bayes to the Training set
            
            classifier = GaussianNB()
            
        
        elif method == "Decision Trees":
            
            #classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
            classifier = DecisionTreeClassifier(random_state = 0)
        
        elif method == "Random Forest":
            
            #classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 0)
            classifier = RandomForestClassifier( random_state = 0, n_jobs = 4)
            
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0, n_jobs = 4)
            
            
        print("Start the PIPELINE !!!")
        
        # Add one transformers and two samplers in the pipeline object
        pipeline = make_pipeline(renn, smote_enn, classifier)

        print()
        print(" Starting CROSS-Validation, with k = 10 folds, with this method: " + method)
        print()
            
        
    #If it is not clear review the link from Stack
    #https://stackoverflow.com/questions/48370150/how-to-implement-smote-in-cross-validation-and-gridsearchcv
        
        for train_index, test_index in kf.split(X,y):
            #print("TRAIN:", train_index, "TEST:", test_index)
            
            X_train, X_test = X[train_index], X[test_index]
            y_train, y_test = y[train_index], y[test_index]
            
            #print("Start Working")

            pipeline.fit(X_train, y_train)
       
            y_hat = pipeline.predict(X_test)
           
            # Making the Confusion Matrix
            
            #print()
            #cm = confusion_matrix(y_test, y_hat)
            #print(cm)
            #print()
            accuracy = accuracy_score(y_test, y_hat)
            F1 = f1_score(y_test, y_hat, pos_label = "1")
            #print(accuracy)
            
            tot_acc[method].append(accuracy)
            tot_F1[method].append(F1)
    
    print("ACCURACY Results")
    print()
    print("Results: ")
    tot_acc = {k:sum(tot_acc[k])/len(tot_acc[k])for k in tot_acc} 
    print()
    print(tot_acc)
    
    print()
    print("F1_Score")
    print()
    print("Results: ")
    tot_F1 = {k:sum(tot_F1[k])/len(tot_F1[k])for k in tot_F1} 
    print()
    print(tot_F1)
    print()
    
    #Now we have to change this path and enter in our new folder
    os.chdir('../')
    print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Cross Validation !!!!")
            
        
            
# =============================================================================
#             print()
#             print(accuracies)
#             print()
#             print("The Accuracy mean is about : " + str(round(accuracies.mean(),2)*100) + "% using " + method)
#             print("The sd of the Accuracy is : " +str(round(accuracies.std(),2)*100)+ "% using " + method)
#             print()
# =============================================================================
            
            ###SI PUò INSERIRE LO SCATTER PLOT DELLE ACCURATEZZE
            ## VEDERE IL LINK
            #https://machinelearningmastery.com/compare-machine-learning-algorithms-python-scikit-learn/
            
            ####K- FOLD AND GRID SEARCH###
            
            # Applying Grid Search to find the best model and the best parameters
            
            
            # Create regularization penalty space
            #penalty = ['l1', 'l2']
            
            # Create regularization hyperparameter space
            #C = np.logspace(0, 4, 10)
            
            # Create hyperparameter options
            #parameters = dict(C=C, penalty=penalty)
            
            #parameters = [{'C': [1, 10, 100, 1000], 'kernel': ['linear']},
                          #{'C': [1, 10, 100, 1000], 'kernel': ['rbf'], 'gamma': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]}]
            
            #grid_search = GridSearchCV(estimator = classifier, param_grid = parameters,
             #                          scoring = 'accuracy', cv = 10, n_jobs = -1)
            
            #grid_search = grid_search.fit(X_train, y_train)
            #best_accuracy = grid_search.best_score_
            #print()
            #print("Best Accuracy are: ")
            #print(best_accuracy)
            #best_parameters = grid_search.best_params_
            #print()
            #print()
            #print("Best Parameters are: ")
            #print(best_parameters)

def GridSearch():
    
    print("Loading Dataset for Grid Search")
    #Dataframe[Label DSCP, Features] --> Structure
    data_frame = pd.read_pickle("data_transformed_for_CrossValidation.pkl")
    
    #Problem to use Recall AND Precision we have to specify which is 0 and 1 tp and tn
    
    # Map dataframe to encode values and put values into a numpy array
    #data_frame[["Label DSCP"]] = data_frame[["Label DSCP"]].apply(pd.to_numeric)
    
    dd_r = "Grid Search"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
    print()
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print()
    print("Starting Grid Search !!!!")
    print()
    
    #Definition of the passages into the Pipeline
    
    #UNDERSAMPLING --> Repeated ENN
    renn = RepeatedEditedNearestNeighbours( random_state = 0, n_neighbors = 5, max_iter = 100, n_jobs= 2)
    
    #OVERSAMPLING --> SMOOTEENN
    smote_enn = SMOTEENN(random_state = 0)
     
    # Make the splits
    n = 10
    kf = StratifiedKFold(n_splits = n, random_state = 0)
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    print()
    print("Possible algorithm about Classification Problem: ")
    
    Ml_Algo = ["Logistic", "SVM", "Random Forest", "XGBoost"]
    print(Ml_Algo)
    print()
    
    print()
    print(data_frame.head())
    print()
    X = data_frame.iloc[:,1:].values
    y = data_frame.iloc[:,0].values
    
    val = []
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
        #Fitting Logistic Regression to the Training set
        
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)
    
        if method == "Logistic" :
            
            classifier = LogisticRegression(random_state = 0, n_jobs = 4)

            # Create regularization penalty space
            penalty = ['l1', 'l2']
        
            # Create regularization hyperparameter space
            #C = np.logspace(0, 4, 10)
            C = [ 0.001, 0.0001, 0.0001]
            
            # Create hyperparameter options
            parameters = {"logisticregression__C":C, "logisticregression__penalty":penalty}
            
        elif method == "SVM":
            
            classifier = SVC(random_state = 0)
            
            parameters = {'svc__kernel': [ "rbf"], 'svc__gamma': [0.1, 0.01, 0.001, 1e-3],
                          'svc__C': [ 1]}
                        
        
        elif method == "Random Forest":
            
            classifier = RandomForestClassifier( random_state = 0, n_jobs = 2)
            
            parameters = {'randomforestclassifier__n_estimators': [17,19, 21, 23, 25],
                          'randomforestclassifier__criterion': ['gini', 'entropy'],
                          'randomforestclassifier__max_features': [None, "auto", "sqrt", "log2"]
                          }
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0, n_jobs = 4)
            
            parameters = {"xgbclassifier__max_depth":[3,4,5,6,7,9],
                          "xgbclassifier__gamma":[0, 0.1, 0.2],
                          "xgbclassifier__colsample_bytree":[0.5,0.6,0.7,0.8,0.9],                
                          "xgbclassifier__n_estimators": [10, 50, 100, 500],
                          "xgbclassifier__learning_rate": [0.1, 0.5, 1],
                          'xgbclassifier__min_child_weight': [1, 3, 4, 5, 6]
                          
                    }
            
            
        print("Start PIPELINE !!!")
        
        # Add one transformers and two samplers in the pipeline object
        pipeline = make_pipeline(renn, smote_enn, classifier)
        #pipeline = make_pipeline(knn)
        print()
        print(" Starting Grid Search, with this method: " + method)
        print()
            
        
    #If it is not clear review the link from Stack
    #https://stackoverflow.com/questions/48370150/how-to-implement-smote-in-cross-validation-and-gridsearchcv
        
        scorers = {
                'precision_score': make_scorer(precision_score, pos_label="1"),
                'recall_score': make_scorer(recall_score, pos_label="1"),
                'accuracy_score': make_scorer(accuracy_score),
                'f1_scorer': make_scorer(f1_score, pos_label="1")
            }
        
        random_search = GridSearchCV(pipeline,  param_grid = parameters , cv = kf,  scoring = scorers, refit = 'recall_score')
        gg = random_search.fit(X, y)
        #a = gg.cv_results_
        #print(a)
        #print(gg.best_estimator_)
        print(gg.best_params_)
        print()
        print(gg.best_score_)
        print()
        val.append(gg.best_params_)
        
    print(val)
    
# =============================================================================
#                           LDA & Oversampling
# =============================================================================

def Oversampling_and_LDA(dataset):
    
    dd_r = "Oversampling_and_LDA"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
        
    
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Oversampling !!!!")
    print()
    print(dataset.head())
    print()
    
    #We are dividing the Ind. Variable to The lable    
    
    #X = dataset.iloc[:, 1:].values
    #y = dataset.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    categorical_features = ["ds_field_ecn", "Protocol", "flag_df","IP_SRC", "IP_DST","Port Important"]
    continuous_features = ["length", "ttl"]
    
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella PCA 
    
    #label = dataframe["Label DSCP"]
    
    #row = X_train.shape[0]
    #y_train = np.reshape(y_train,(row,1))

    #data = np.concatenate((y_train, X_train ), axis=1)
    #col = dataset.columns

    #df = pd.DataFrame(data = data, columns = col)
    
    print("These are the variables selected:")
    print()
    print("For the CATEGORICAL we have: " )
    print(categorical_features)
    print()
    print("For the CONTINUOUS we have: ")
    print(continuous_features)
    print()
    print()
    
    print()
    print(dataset.head())
    print()
    #Summary of the continuous feature
    print("This is a summary for the continuos Features")
    #X_train[continuous_features].describe()
    
    #Normalize the Continuous variables
    
    mms = MinMaxScaler()
    mms.fit(dataset[continuous_features])
    data_transformed = mms.transform(dataset[continuous_features])
    
    #Creation of a new DataFrame
    data_transformed = pd.DataFrame(data_transformed, columns= continuous_features)
    
    
    #Drop the index to concatenate in a correct way the 2 dataframes
    dataset = dataset.reset_index(drop = True) 
    
    #Add the categorical features to the new data frame normalized
    data_transformed[categorical_features] = dataset[categorical_features]
    
    print()
    print("This is the new DataFrame: ")
    print(data_transformed.head())
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    
    for col in categorical_features:
        dummies = pd.get_dummies(data_transformed[col], prefix=col)
        data_transformed = pd.concat([data_transformed, dummies], axis=1)
        data_transformed.drop(col, axis=1, inplace=True)
    
    print(data_transformed.head())
    data_transformed["Label DSCP"] = dataset["Label DSCP"]
    print(Counter(data_transformed["Label DSCP"]))
    
    cols = data_transformed.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    data_transformed = data_transformed.reindex(columns= cols)
    
    print("Coluuuuuuums: ")
    print(data_transformed.columns)
    print()
    
    X = data_transformed.iloc[:, 1:].values
    y = data_transformed.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    
    X_train = data_transformed.iloc[:, 1:].values
    y_train = data_transformed.iloc[:, 0].values
    
    print("UNDERSAMPLING:")
    print()
    print("START ENN")
    print()
    print("Begin")
    print(sorted(Counter(y).items()))
    
    enn = EditedNearestNeighbours(random_state = 0,  n_neighbors = 20, n_jobs=2,)
    X_under_resampled, y_under_resampled = enn.fit_resample(X_train, y_train)
    
    print()
    print("After")
    print(sorted(Counter(y_under_resampled).items()))
    
    print()
    print("START SMOTEENN")
    #Making the SMOOTEENN
    smote_enn = SMOTEENN(random_state=0)
    
    print()
    print("Beginning Distribution: ")
    print(sorted(Counter(y_under_resampled).items()))
    
    #Resample about X and y
    X_resampled, y_resampled = smote_enn.fit_resample(X_under_resampled, y_under_resampled)
    
   
    print()
    print("New Distribution: ")
    print(sorted(Counter(y_resampled).items()))
    
    #TRAIN DATA FRAME
    row = X_resampled.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_resampled = np.reshape(y_resampled,(row,1))

    data = np.concatenate((y_resampled, X_resampled), axis=1)
    print()
    print(data)
    #col = ["Label DSCP","PCA_1", "PCA_2"]
    
    col = data_transformed.columns
    
    df_balanced_train = pd.DataFrame(data = data, columns = col)
    
    etichetta_test = [ "0" for i in range(df_balanced_train.shape[0])]
    
    
    idx = len(df_balanced_train.columns)
    df_balanced_train.insert(loc=idx, column='Etichetta Test', value= etichetta_test)
    
    print(df_balanced_train.head())
    
    
    #TEST DATA FRAME
    row = X_test.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_test = np.reshape(y_test,(row,1))

    data_test = np.concatenate((y_test, X_test), axis=1)
    print()
    print(data_test)
    #col = ["Label DSCP","PCA_1", "PCA_2"]
    
    col = data_transformed.columns
    
    df_balanced_test = pd.DataFrame(data = data_test, columns = col)
    
    etichetta_test = [ "1" for i in range(df_balanced_test.shape[0])]
    
    
    idx = len(df_balanced_test.columns)
    df_balanced_test.insert(loc=idx, column='Etichetta Test', value= etichetta_test)
    
    print(df_balanced_test.head())
    
    df_balanced = pd.concat([df_balanced_train, df_balanced_test])
    print()
    print("NUUUUUL")
    print(df_balanced.isnull().sum())
    #Taking the train dataset
    #train = np.array(data_transformed)

    print()
    print("Staaaaaaart LDA !!!")
    
    
    # Applying LDA
    lda = LDA(n_components = 2)
    lda_data = lda.fit_transform(df_balanced.iloc[:,1:-1].values, df_balanced.iloc[:,0].values )
   
    
    pre_var = np.round(lda.explained_variance_ratio_ * 100 , decimals = 1)
    
    
    dd_r = "LDA"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
     
    labels = ["LD" + str(x) for x in range(1, len(pre_var)+1)]
    
    
    lda_df = pd.DataFrame(lda_data, columns = labels)

    lda_df["Label DSCP"] = df_balanced["Label DSCP"].values
    cols = lda_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    lda_df = lda_df.reindex(columns= cols)
    
    
    lda_df["Etichetta Test"] = df_balanced["Etichetta Test"].values
    cols = lda_df.columns.tolist()
    cols.insert(len(cols), cols.pop(cols.index("Etichetta Test")))
    lda_df = lda_df.reindex(columns= cols)
    
    
    print("Daje fino a qui")
    #SPLIT DATA FRAME
    
    
    print()
    print("Classification Time")
    
    #pca_dataframe = PCA_decomposition(df_balanced)

    #MIGLIORARE IL CODICE PERCHé STIAMO PERDENDO IL REALE TEST
    #TRASPORTARE LA PARTE DI INTERESSE QUI VEDENDO LOGISTIC E RANDOM FOREST CON
    #IGRAFICI
    
    train = lda_df[lda_df['Etichetta Test'] == "0" ]
    test  = lda_df[lda_df['Etichetta Test'] == "1" ]  
    
    X_train = train.iloc[:, 1:-1].values
    y_train = train.iloc[:, 0].values
    
    X_test =  test.iloc[:, 1:-1].values
    y_test =  test.iloc[:, 0].values
    
    
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", "Random Forest"]
    
    print()
    print("Possible algorithm about Classification Problem")
    print(Ml_Algo)
    
    
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
    # Fitting Logistic Regression to the Training set
        
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)

        if method == "Logistic" :
        
            from sklearn.linear_model import LogisticRegression
            classifier = LogisticRegression(random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "SVM con Kernel":
            
            # Fitting Kernel SVM to the Training set
            from sklearn.svm import SVC
            classifier = SVC(kernel = 'rbf', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Naive Bayes":
            # Fitting Naive Bayes to the Training set
            from sklearn.naive_bayes import GaussianNB
            classifier = GaussianNB()
            classifier.fit(X_train, y_train)
        
        elif method == "Decision Trees":
            # Fitting Decision Tree Classification to the Training set
            from sklearn.tree import DecisionTreeClassifier
            classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Random Forest":
            # Fitting Random Forest Classification to the Training set
            from sklearn.ensemble import RandomForestClassifier
            classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 0)
            classifier.fit(X_train, y_train)
        
        # Predicting the Test set results
        y_pred = classifier.predict(X_test)
        
        # Making the Confusion Matrix

        
        cm = confusion_matrix(y_test, y_pred)
        
        print()
        print("We obtained this result: ")
        print(cm)
        np.save("./" + nn_dir + "/ConfusionMatrix_using_" + method, cm)
        
        accuracy = accuracy_score(y_test, y_pred)
        print("This is the Accuracy score: " + str(accuracy))
        
        #precision = precision_score(y_test, y_pred)
        #print("The precision is: " + str(precision))
        
        #recall = recall_score(y_test, y_pred)
        #print("This is the recall score: " + str(recall))
      
        # Visualising the TRAINING set results
        

    
