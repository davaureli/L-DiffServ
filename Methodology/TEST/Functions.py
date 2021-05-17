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
from collections import Counter

#from sklearn import preprocessing
#from sklearn.preprocessing import StandardScaler
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA
from sklearn.preprocessing import MinMaxScaler

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix


#Cleaning Dataset through Under and Over sampling
from imblearn.combine import SMOTEENN
from imblearn.under_sampling import EditedNearestNeighbours


import warnings
warnings.filterwarnings("ignore")


#Data about the mapping between ASN and Ip addressees updated to 2019/March
#asndb = pyasn.pyasn("IpAsn2019.dat")


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

def extract_Info_pckt(file_name, lista_packet_ICMP):
    
    pcap = pyshark.FileCapture(file_name)

    tt = ["Label DSCP", "header len", "ds_field","ds_field_ecn", "length", "Protocol" ,"flag_df",
          "flag_mf", "flag_rb", "fragment_offset", "ttl", "IP_SRC", "IP_DST","src_port",
          "dst_port","time"] 
    
    totale = []
    print("Now I'm working on: " + file_name)
    print()
    
    #VM
    title = (file_name.split("/")[-1].split(".")[-2])
    print("This is title : " + title)
    #Local
    #title = (file_name.split("/")[-1].split(".")[0])[12:]
    print(title)
    
    
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
        #if 'IP' in packet :
            
            
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
            
            
            #### Extraction of the Ip Source and Ip Destination###
            
            source = packet.ip.src
            valori.append(source)
            
            destination = packet.ip.dst
            valori.append(destination)
  
            #### Extraction of the Port ####
            if "UDP" in packet:
                valori.append(packet.udp.srcport)
                valori.append(packet.udp.dstport)

            elif "TCP" in packet :
                valori.append(packet.tcp.srcport)
                valori.append(packet.tcp.dstport)            
                
            else:
                #Protocol as IP and ICMP e Ws.Short avranno come porta -1
                valori.append(-1)
                valori.append(-1)
                
            if "ICMP" in packet:
                lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))
            
            
            #Time will be used for the simulation
            time = float(packet.sniff_timestamp)
            valori.append(time)
             
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
        
    print("Sto salvando su shareCluster")
    #Save in a share folder for making then the cluster
    with open('../shareCluster/' + title + '.pkl', 'wb') as f:
        pickle.dump(tot_dat, f)
    print("Salvato su shareCluster")
    
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
    #we mantain an integer value as DSCP key.    In totale is stored the total number of packets with DSCP label
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
    
    ### Bar Chart #####

    plt.rcdefaults()
    labels = list(percentage.keys())
    
    sizes = [ round(percentage[elem]*100/total_packet,4)  for elem in labels]
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
    plt.title('DSCP Distribution', fontsize = 'medium')
    #plt.grid(True)
    plt.legend(h,legend, loc= "center right")
    plt.tight_layout()
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
    plt.legend(h,legend, loc= "center right", fontsize = "small")
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
    plt.legend(h,legend)
    plt.tight_layout()
    plt.savefig("Images_Distribution/Distribution DSCP without BE and NotKnown.png", dpi = 150, figsize=(12,6))
    #plt.show()
    plt.close()
    print("Saved the third picture DSCP")
    


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
    '''
    X = data_transformed.iloc[:, 1:].values
    y = data_transformed.iloc[:, 0].values
    
    # Splitting the dataset into the Training set and Test set al 25% il Test 
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
    
    
    X_train = data_transformed.iloc[:, 1:].values
    y_train = data_transformed.iloc[:, 0].values
    
    print("START SMOTEEEEEEENNNNN")
    #Making the SMOOTEENN
    smote_enn = SMOTEENN(random_state=0)
    
    print()
    print("Beginning Distribution: ")
    print(sorted(Counter(y_train).items()))
    
    #Resample about X and y
    X_resampled, y_resampled = smote_enn.fit_resample(X_train, y_train)
    
    print()
    print("New Distribution: ")
    print(sorted(Counter(y_resampled).items()))
    
    #Train Dataframe
    row = X_resampled.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_resampled = np.reshape(y_resampled,(row,1))

    data = np.concatenate((y_resampled, X_resampled), axis=1)
    print()
    print(data)
    #col = ["Label DSCP","PCA_1", "PCA_2"]
    
    col = data_transformed.columns
    
    df_balanced = pd.DataFrame(data = data, columns = col)
    
    print(df_balanced.head())
    
    #CANCELLARE DA QUI
    
    X_train = df_balanced.iloc[:, 1:].values
    y_train = df_balanced.iloc[:, 0].values
    
    
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
      
    
    #Taking the train dataset
    #train = np.array(data_transformed)

    print()
    print("Staaaaaaart PCA !!!")
    n_comp = 3
    
    pca = PCA(n_components = n_comp)
    pca.fit(df_balanced.iloc[:,1:])
    pca_data = pca.transform(df_balanced.iloc[:,1:])
    
    pre_var = np.round(pca.explained_variance_ratio_ * 100 , decimals = 1)
    
    
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
    for i in range(df_balanced.shape[0]):
        dscp  = list(df_balanced.iloc[[i]]["Label DSCP"].values)[0]
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

    pca_df["Label DSCP"] = df_balanced["Label DSCP"]
    cols = pca_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    pca_df = pca_df.reindex(columns= cols)
    
    
    print("Daje fino a qui")
    
    print()
    print("Classification Time")
    
    #pca_dataframe = PCA_decomposition(df_balanced)

    #MIGLIORARE IL CODICE PERCHé STIAMO PERDENDO IL REALE TEST
    #TRASPORTARE LA PARTE DI INTERESSE QUI VEDENDO LOGISTIC E RANDOM FOREST CON
    #IGRAFICI
    
    X_train = df_balanced.iloc[:, 1:].values
    y_train = df_balanced.iloc[:, 0].values
    
    
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
'''

    
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
        

    
