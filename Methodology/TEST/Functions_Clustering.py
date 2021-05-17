# -*- coding: utf-8 -*-
"""
Created on Thu Apr 25 21:25:15 2019

@author: Davide
"""


import pandas as pd
import numpy as np
from collections import Counter
import math
import operator
import pickle


import matplotlib.pyplot as plt

#Dimensionality Reduction
from sklearn.preprocessing import MinMaxScaler

from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA
#from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.decomposition import PCA

from sklearn.neighbors import NearestNeighbors

#Clustering
from sklearn.cluster import KMeans
from sklearn.mixture import GaussianMixture
# Compute clustering with MeanShift
from sklearn.cluster import DBSCAN



#Evaluation metrics
from sklearn.metrics import silhouette_samples, silhouette_score


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


def Cleaning_for_Clustering(dataframe):
    
    #We are excluding from the variables "dsfield" because it synthesizes the DSCP field and
    #ECN field. It is not useful to include in the classification problems
    
    variables = [ i for i in dataframe.columns if i != 'ds_field']
    print("We start considering these variables: ")
    print(variables)
    
    #Transform into numeric the caracteristics collect as strings but the could be considered
    #as numeric for having the CORRELATION plot
    
    
    #first_clean['Label DSCP'] = pd.to_numeric(tot_dat['Label DSCP'])
    dataframe['flag_df'] = pd.to_numeric(dataframe['flag_df'])
    dataframe['flag_mf'] = pd.to_numeric(dataframe['flag_mf'])
    
    
    #Now we are excluding the ones with a std equal to 0 so the dictionary created by Counter
    #will have only one element so 1 key.    
    
    mantain_col = []
    for col in variables:
        diz = Counter(dataframe[col])
        if len(diz) >= 1:
            mantain_col.append(col)
    #If we use as dataframe only the one with Label DSCP == 0 or not we will exclude this
    #Variable (column)      
    
    
    #Now we have concluded the first kind of cleaning
    first_clean =  dataframe[mantain_col].copy()
    print(first_clean.columns)

#NOT USEFUL PART CAUSE NOW WE ARE COMBINING DATAFRAME FROM DIFFERENT PART
# =============================================================================   
    #Variables considered numeric for our corr plot, we not included the Label DSCP 
    #Cause 
#    numeric = ["length", "flag_df", "flag_mf", "ttl"]
    
#    numeric = [ va for va in first_clean.columns if va in numeric]
  
   
#    data = first_clean[numeric]
  

#     corr = data.corr()
#     fig = plt.figure()
#     ax = fig.add_subplot(111)
#     cax = ax.matshow(corr,cmap='coolwarm', vmin=-1, vmax=1)
#     fig.colorbar(cax)
#     ticks = np.arange(0,len(data.columns),1)
#     ax.set_xticks(ticks)
#     plt.xticks(rotation=90)
#     ax.set_yticks(ticks)
#     ax.set_xticklabels(data.columns)
#     ax.set_yticklabels(data.columns)
#     #for VM
#     #plt.savefig("./Images_Distribution/CorrelationPlot.png", dpi = 150, figsize=(12,6))
#     #for LOCAL
#     plt.savefig("./Images_Distribution/"+ title +".png", dpi = 150, figsize=(12,6))
#     #plt.show()
#     plt.close()
#     print("Saved the Correlation Plot")
#     
# =============================================================================
    ### IP Part ###

#    ## Remove all the packets with an unknown AS, IP signed as -1
#    first_clean = first_clean.drop(first_clean[first_clean["IP_SRC"] == -1].index)
#    first_clean = first_clean.drop(first_clean[first_clean["IP_DST"] == -1].index)
#    
#    ### IP Source ### ---> We have to select the number that mantain the max Info 
#    a = Counter(first_clean["IP_SRC"])
#    for i in range(1, len(a.most_common())):
#        a_buoni = a.most_common(i)
#        X = [elem[1] for elem in a_buoni]
#        
#        par_tot = sum(X)
#        tot = sum(list(a.values()))
#        percent = par_tot*100 / tot
#        
#        if percent >= 85:
#            break
#    print("The number of element selected for IP_Src are: " + str(i))
#    print("The percentage of info is : " + str(round(percent,2)) + "%")
#    
#    Ip_src_togliere =[elem[0] for elem in a.most_common() if elem not in a_buoni ] 
#    
#    
#    ### IP Destination ### ---> Abbiamo mantenuto l' 85% dell'informazione
#    r = Counter(first_clean["IP_DST"])
#    
#    for j in range(1, len(r.most_common())):
#        r_buoni = r.most_common(j)
#        Y = [elem[1] for elem in a_buoni]
#        
#        par_tot = sum(Y)
#        tot = sum(list(r.values()))
#        percent = par_tot*100 / tot
#        
#        if percent >= 85:
#            break
#    print("The number of element selected for IP_Dst are: " + str(j))
#    print("The percentage of info is : " + str(round(percent,2)) + "%")
#    
#    Ip_dst_togliere =[elem[0] for elem in r.most_common() if elem not in r_buoni] 
#                      
#    print()
#    
#    print("Removing the IP from SRC and DST ")
#    
#    first_clean["IP_SRC"] = first_clean["IP_SRC"].replace(Ip_src_togliere, -1)
#    first_clean["IP_DST"] = first_clean["IP_DST"].replace(Ip_dst_togliere, -1)
#    print(first_clean.head())
#    print(type(first_clean))
#    ### We can now remove the observations with IP in SRC or DST equals to -1
#    ### and then we can go on
#    
#    
#    #first_clean = first_clean.loc[(first_clean["IP_SRC"] != -1) & (first_clean["IP_DST"] != -1)]
#    
#    print(first_clean.head())
    print()
    print("Now we can go on working with PORT_Number")
    
    
    #### PORT Part####
    
    ## We 'll select the Port number, in src or dst most important with the highest value
    ## of occurrences
    
    ##First of all we have to join the occurrences of Port SRC and Port Dst
    
    ##Source Port##
    a = Counter(first_clean["src_port"])
    
    #len(a.most_common())
    for i in range(1, 100):
        a_buoni = a.most_common(i)
        X = [elem[1] for elem in a_buoni]
###        
        par_tot = sum(X)
        tot = sum(list(a.values()))
        percent = par_tot*100 / tot
###        
        if percent >= 85:
            break
    print("The number of element selected for src_Port is: " + str(i))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
###    
    src_Port_togliere =[elem[0] for elem in a.most_common() if elem not in a_buoni ] 
    

    ##Destination Port##
    r = Counter(first_clean["dst_port"])
    
    #len(r.most_common())
    for j in range(1, 100):
        r_buoni = r.most_common(j)
        Y = [elem[1] for elem in r_buoni]
###        
        par_tot = sum(Y)
        tot = sum(list(r.values()))
        percent = par_tot*100 / tot
###        
        if percent >= 85:
            break
    print("The number of element selected for dst_Port is: " + str(j))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
###    
    dst_Port_togliere =[elem[0] for elem in r.most_common() if elem not in r_buoni]
    


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
    
    for h in range(1, len(v.most_common()) + 1):
        v_buoni = v.most_common(h)
        W = [elem[1] for elem in v_buoni]
    
        par_tot = sum(W)
        tot = sum(list(v.values()))
        percent = par_tot*100 / tot
    
        if percent >= 85:
            break
    print("The number of element selected for the PORTS_Number are: " + str(h))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
    
    
    port_delete =[elem[0] for elem in v.most_common() if elem not in v_buoni ]     
    
    ##Final dataset
    
    #final_data = data_clean[variabili].copy()
    
    #0 porte meno importanti e presenti delle prime
    first_clean["Port Important"] = first_clean["Port Important"].replace(port_delete, 0)
    '''
    #Per le porte messo -1 ai protocolli che non utilizzano la porta come ICMP 
    # per le porte meno conosciute messo 0 ed il resto lasciato il numero,
    #idea giusta ???
    
    print("Removing the Ports from SRC and DST ")
###    
    first_clean["src_port"] = first_clean["src_port"].replace(src_Port_togliere, 0)
    first_clean["dst_port"] = first_clean["dst_port"].replace(dst_Port_togliere, 0)
    print(first_clean.head())
    print(type(first_clean))
    
    
    first_clean["Label DSCP"] = dataframe["Label DSCP"]
    cols = first_clean.columns.tolist()
    cols.insert(0, cols.pop(cols.index('Label DSCP')))
    first_clean = first_clean.reindex(columns= cols)
    
    #variabili = ['Label DSCP', 'ds_field_ecn', 'length', 'Protocol', 'flag_df',
    #'flag_mf', 'fragment_offset', 'ttl', 'IP_SRC', 'IP_DST', 'Port Important']
    
    return first_clean


def extractIndexToDelete(data, columns_observed, lista_index):

    DF = data[columns_observed]
    index_to_delete = DF[DF.apply(lambda x: min(x) == max(x), 1)].index
    print("Indici")
    print(len(index_to_delete))
    for i in index_to_delete:
        lista_index.append(i)


def detect_indexToDelete(name_file, dizionario_check):
    
    print("We work with:  " + str(name_file))
    dataframe = pd.read_pickle(name_file)
    
    label_hash = []
    for i in range(0,dataframe.shape[0]):

        source = dataframe.loc[i]["IP_SRC"]
        destination = dataframe.loc[i]["IP_DST"]
        src_port = dataframe.loc[i]["src_port"]
        dst_port = dataframe.loc[i]["dst_port"]
        protocol = dataframe.loc[i]["Protocol"]
        hash_id = hash(str(source) + str(destination) + str(src_port) + str(dst_port) + str(protocol))
        if i == 0:
            print(source)
            print(destination)
            print(src_port)
            print(dst_port)
            print(protocol)
            print(hash_id)
            print()
        label = dataframe.loc[i]["Label DSCP"]
        
        label_hash.append(hash_id)
        
#            
        if hash_id not in dizionario_check:
            dizionario_check[hash_id] = [label]
        elif hash_id in dizionario_check and label not in dizionario_check[hash_id]:
            lista_nuova = dizionario_check[hash_id]
            lista_nuova.append(label)
            dizionario_check[hash_id] = lista_nuova
            
    dataframe["Hash"] = label_hash
    
    print("Salviamo il nuovo dataframe")
    dataframe.to_pickle(name_file)
            
    #return dizionario_check, index_to_delete



def Transform_data(dataset):
    
    print("Starting DataFrame")
    print()
    print(dataset.head())
    print()
    print("The columns are: ")
    print()
    print(dataset.columns)
    print()
    
    #Dividing the numerical from the categorical variables
    
    #categorical_features = ["ds_field_ecn", "Protocol", "flag_df",
    #                           "IP_SRC", "IP_DST","Port Important"]
    
    #We are now working without Ip Src and Ip Dst
    categorical_features = [ "Protocol","src_port", "dst_port"] #tolto flag df
    continuous_features = ["length", "ttl"]
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella PCA 
    
    
    print("These are the variables selected:")
    print()
    print("For the CATEGORICAL we have: " )
    print(categorical_features)
    print()
    print("For the CONTINUOUS we have: ")
    print(continuous_features)
    print()
    
    print("Start Working with the Numerical, we normalize them")
    print()

    #Summary of the continuous feature
    
    print("This is a summary for the continuos Features")
    print()
    
    dataset[continuous_features].describe()
    
    #Normalize the Continuous variables
    
#    mms = MinMaxScaler()
#    mms.fit(dataset[continuous_features])
#    
#    ### SAVE THE .fit Model
#    ###filename = './Test_Classification/MinMaxScaler_fit.sav'
#    ###pickle.dump(mms, open(filename, 'wb'))
#    
#    ### SAVE THE .fit Model
#    ###filename = './Test_Classification/MinMaxScaler_fit.sav'
#    ###pickle.dump(mms, open(filename, 'wb'))
    
    #data_transformed = mms.transform(dataset[continuous_features])
    
    #NOW Load our saved model 
    
    # load the model from disk
    loaded_model = pickle.load(open("MinMaxScaler_fit_0403.sav", 'rb'))
    
    #To Apply transformation uncomment below row
    #data_transformed = loaded_model.transform(dataset[continuous_features])
    data_transformed = dataset[continuous_features]
    print(data_transformed)
    
    
    #Creation of a new DataFrame
    data_transformed = pd.DataFrame(data_transformed, columns= continuous_features)
        
    #Drop the index to concatenate in a correct way the 2 dataframes
    dataset = dataset.reset_index(drop = True) 
    
    #Add the categorical features to the new data frame normalized
    data_transformed[categorical_features] = dataset[categorical_features]
    
    
    #AGGIUNTA PER IL MODELLO SOLO LE VARIABILI NUMERICHE 
    data_transformed = data_transformed[categorical_features]
    
    print()
    print("This is the new DataFrame: ")
    print(data_transformed.head())
    print()
    
    print("We continue to work, now on the categorical variables")
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    
    for col in categorical_features:
        #Inserito il drop first drop_first=True
        #dummies = pd.get_dummies(data_transformed[col], prefix=col, drop_first=True )        
        dummies = pd.get_dummies(data_transformed[col], prefix=col)
        data_transformed = pd.concat([data_transformed, dummies], axis=1)
        data_transformed.drop(col, axis=1, inplace=True)
        
    print()
    print("This is the new DataFrame after the transformations: ")
    print()
    print(data_transformed.head())
    print()
    
    #We now append the label
    data_transformed["Label DSCP"] = dataset["Label DSCP"]
    
    print("These are the occurrences for the DSCP")
    print(Counter(data_transformed["Label DSCP"]))
    
    #Put the label into the first column
    cols = data_transformed.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    
    data_transformed = data_transformed.reindex(columns= cols)
    # Salvare il dataframe dataTransformed, 
    # dopo eseguiremo cross validation su questo
    
    #Per ora non ci concentriamo sulla cross validation
    #data_transformed.to_pickle("data_transformed_for_CrossValidation.pkl") 
    
    print(" Coluuuuuuums with the correct order : ")
    print(data_transformed.columns)
    print()
    
    return data_transformed



def dimensionality_reduction(dataframe ,n_comp = 3, method = ["PCA", "LDA"]):
    
    for md in method:
        
        print("Now we work with this method : " + md)
        
        if md == "PCA":
    
            pca = PCA(n_components = n_comp, random_state=42)
            pca.fit(dataframe.iloc[:,1:])
            pca_data = pca.transform(dataframe.iloc[:,1:])
            
            #The percentage of explained Variance
            pre_var = np.round(pca.explained_variance_ratio_ * 100 , decimals = 1)
            
            labels = ["PC" + str(x) for x in range(1, len(pre_var)+1)]
            
            reduction_df = pd.DataFrame(pca_data, columns = labels)
            
        elif md == "LDA":
            
            lda = LDA(n_components = 3)
            #Here we specify both X and y
            lda.fit(dataframe.iloc[:,1:].values, dataframe.iloc[:,0].values)
            
            ### SAVE the LDA .fit Model
            filename = '../Test_Classification/LDA_fit_0403.sav'
            pickle.dump(lda, open(filename, 'wb'))
            
            #Here we specify only the x values not y
            lda_data = lda.transform(dataframe.iloc[:,1:].values)

            #The percentage of explained Variance
            pre_var = np.round(lda.explained_variance_ratio_ * 100 , decimals = 1)
            
            labels = ["LD" + str(x) for x in range(1, len(pre_var)+1)]
            
            reduction_df = pd.DataFrame(lda_data, columns = labels)            
            
        
        #Adding the Label values
        
        reduction_df["Label DSCP"] = dataframe["Label DSCP"].values
        cols = reduction_df.columns.tolist()
        cols.insert(0, cols.pop(cols.index("Label DSCP")))
        reduction_df = reduction_df.reindex(columns= cols)
        
        print()
        print("This is the obtained new Dataframe with the new Components")
        print()
        print(reduction_df.head())
        print()
            
# =============================================================================
#         #Plot these results about the new 3 components
# =============================================================================
        
        ##Component 1
        
        print("Component_1")
        print()
        
        if md == "PCA":
            loading_scores = pd.Series(pca.components_[0], index = dataframe.iloc[:,1:].columns )
        elif md == "LDA":
            loading_scores = pd.Series(lda.coef_[0], index = dataframe.iloc[:,1:].columns )

        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:10].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_PC1_' + md + '.csv')
                
        ##Component 2       
        
        print("Component2")
        print()
        
        if md == "PCA":
            loading_scores = pd.Series(pca.components_[1], index = dataframe.iloc[:,1:].columns )
        elif md == "LDA":
            loading_scores = pd.Series(lda.coef_[1], index = dataframe.iloc[:,1:].columns )
            
        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:10].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_PC2_' + md + '.csv')
        
        #Component 3
        
        print("Component3")
        print()
        
        if md == "PCA":
            loading_scores = pd.Series(pca.components_[2], index = dataframe.iloc[:,1:].columns )
        elif md == "LDA":
            loading_scores = pd.Series(lda.coef_[2], index = dataframe.iloc[:,1:].columns )
        
        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:10].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_PC3_' + md + '.csv')
        
# =============================================================================
#                               BARCHART for the Variance
# =============================================================================
        
        print()
        print("Starting make the bar chart for the explained Variance")
        
        plt.bar(x=range(1,len(pre_var)+1), height=pre_var, tick_label = labels)
        plt.ylabel("Percentage of Explained Variance")
        plt.xlabel("Principal Component")
        plt.title("Screen Plot for Explained_Variance ")
        plt.savefig(md + '_Explained_Variance.png')
        #plt.show()
        plt.close()
        
        
# =============================================================================
#         ###############         COLOR           ####################
# =============================================================================
        
        # Possible color we can define here the color to the possible classes
        
        #cc = {Class:Color}
        
        cc ={'AF': "Black",
         'Critical voice RTP':"Red",
         'Network or Intenetwork control':"Blue",
         'Not Known':"Yellow",
         'best effort':"Green"} 
        
        #inv_cc = {Color:Class}
        inv_cc = {v: k for k, v in cc.items()}
        
        #List of colors, for each packet we will have a specific color
        color = [] 
        
        for i in range(dataframe.shape[0]):
            dscp  = list(dataframe.iloc[[i]]["Label DSCP"].values)[0]
            color.append(cc[dscp])
        
# =============================================================================
#                               PLOT in 2D
# =============================================================================
        
        print()
        print("Plot 2D " + md)
        print()
        
        fig = plt.figure(figsize=(10,6))
        
        #plt.scatter(reduction_df.PC1, reduction_df.PC2, c = color)
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        
        x = reduction_df.PC1
        y = reduction_df.PC2
                
        unique = list(set(cc))
        
        classes = [inv_cc[i] for i in color]
        
        colors = [ cc[i] for i in unique]
        
        for i, u in enumerate(unique):
            xi = [x[j] for j  in range(len(x)) if classes[j] == u]
            yi = [y[j] for j  in range(len(x)) if classes[j] == u]
            plt.scatter(xi, yi, c=colors[i], label=str(inv_cc[colors[i]]))
        
        plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.title("My" + md + "Graph")
        plt.legend(loc="upper left", numpoints=1, fontsize=8)
        plt.savefig(md + '_Results2D.png', dpi = 150, figsize=(10,6))
        #plt.show()
        plt.close()
        
# =============================================================================
#                               PLOT in 3D
# =============================================================================
        
        print()
        print("Plot 3D " + md)
        print()
         
        fig = plt.figure(figsize=(10,6))
        ax = fig.add_subplot(111, projection='3d')
        
        x = reduction_df.PC1
        y = reduction_df.PC2
        z = reduction_df.PC3
            
        unique = list(set(cc))
        
        classes = [inv_cc[i] for i in color]
        
        colors = [ cc[i] for i in unique]
        
        for i, u in enumerate(unique):
            xi = [x[j] for j  in range(len(x)) if classes[j] == u]
            yi = [y[j] for j  in range(len(x)) if classes[j] == u]
            zi = [z[j] for j  in range(len(x)) if classes[j] == u]
            ax.scatter(xi, yi, zi, c=colors[i], label=str(inv_cc[colors[i]]))
        
        ax.set_xlabel("PC1 - {0}%" .format(pre_var[0]))
        ax.set_ylabel("PC2 - {0}%" .format(pre_var[1]))
        ax.set_zlabel("PC3 - {0}%" .format(pre_var[2]))
        
        plt.title(md + " Results in 3D")
        plt.legend(loc="upper left", numpoints=1, fontsize=8)
        plt.savefig(md + "_Results3D.png", dpi = 150, figsize=(10,6))
        #plt.show()
        plt.close()
        
    #Osservando i valori ottenuti decidiamo di riprendere il dataframe 
    #generato utilizzando LDA
        
    return reduction_df


