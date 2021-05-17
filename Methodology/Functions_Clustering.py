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

#Per salvare in un csv i centroidi
from numpy import savetxt

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
    
    #Transform into numeric the caracteristics collect as strings but they could be considered
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
            
#    if "Protocol" not in mantain_col:
#        mantain_col.append("Protocol")
#    elif "src_port" not in mantain_col:
#        mantain_col.append("src_port")
#    elif "dst_port" not in mantain_col:
#        mantain_col.append("dst_port")
    
    #If we use as dataframe only the one with Label DSCP == 0 or not we will exclude this
    #Variable (column)      
    
    
    #Now we have concluded the first kind of cleaning
    first_clean =  dataframe[mantain_col].copy() 

# NOT USEFUL PART CAUSE NOW WE ARE COMBINING DATAFRAME FROM DIFFERENT PART
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

###    ## Remove all the packets with an unknown AS, IP signed as -1
#    first_clean = first_clean.drop(first_clean[first_clean["IP_SRC"] == -1].index)
#    first_clean = first_clean.drop(first_clean[first_clean["IP_DST"] == -1].index)
###    
###    ### IP Source ### ---> We have to select the number that mantain the max Info 
#    a = Counter(first_clean["IP_SRC"])
#    for i in range(1, len(a.most_common())):
#        a_buoni = a.most_common(i)
#        X = [elem[1] for elem in a_buoni]
###        
#        par_tot = sum(X)
#        tot = sum(list(a.values()))
#        percent = par_tot*100 / tot
###        
#        if percent >= 85:
#            break
#    print("The number of element selected for IP_Src are: " + str(i))
#    print("The percentage of info is : " + str(round(percent,2)) + "%")
###    
#    Ip_src_togliere =[elem[0] for elem in a.most_common() if elem not in a_buoni ] 
###    
###    
###    ### IP Destination ### ---> Abbiamo mantenuto l' 85% dell'informazione
#    r = Counter(first_clean["IP_DST"])
###    
#    for j in range(1, len(r.most_common())):
#        r_buoni = r.most_common(j)
#        Y = [elem[1] for elem in a_buoni]
##        
#        par_tot = sum(Y)
#        tot = sum(list(r.values()))
#        percent = par_tot*100 / tot
###        
#        if percent >= 85:
#            break
#    print("The number of element selected for IP_Dst are: " + str(j))
#    print("The percentage of info is : " + str(round(percent,2)) + "%")
###    
#    Ip_dst_togliere =[elem[0] for elem in r.most_common() if elem not in r_buoni] 
###                      
#    print()
###    
#    print("Removing the IP from SRC and DST ")
###    
#    first_clean["IP_SRC"] = first_clean["IP_SRC"].replace(Ip_src_togliere, -1)
#    first_clean["IP_DST"] = first_clean["IP_DST"].replace(Ip_dst_togliere, -1)
#    print(first_clean.head())
#    print(type(first_clean))

###    ### We can now remove the observations with IP in SRC or DST equals to -1
###    ### and then we can go on    

    
#    #first_clean = first_clean.loc[(first_clean["IP_SRC"] != -1) & (first_clean["IP_DST"] != -1)]
   
#    print(first_clean.head())
    
    print()
    print("Now we can go on, working with PORT_Number")
    print()
    
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
    
    #Here we extract the Port fondamental for each packet
    
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
    print()
    
    print()
    print("Richiesta Secci")
    print()
    
    #Final cleaning of the Important Port mantaining only the % specified
    v = Counter(first_clean["Port Important"])
    
    #Salvare il dizionario delle porte
    with open('dizionario_porte_occorrenze.pkl', 'wb') as handle:
        pickle.dump(v, handle, protocol=pickle.HIGHEST_PROTOCOL)
    
    for h in range(1, len(v.most_common()) + 1):
        v_buoni = v.most_common(h)
        W = [elem[1] for elem in v_buoni]
    
        par_tot = sum(W)
        tot = sum(list(v.values()))
        percent = par_tot*100 / tot
        
        #fino ad ora utilizzato 85 ora mettiamo 99
        if percent >= 90:
            break
    
    print()
    print("The number of element selected for the PORTS_Number is: " + str(h))
    print("The percentage of info is : " + str(round(percent,2)) + "%")
    
    #Extraction of Foundamental Port to delete
    port_delete =[elem[0] for elem in v.most_common() if elem not in v_buoni ]     
    
    ##Final dataset
    
    #final_data = data_clean[variabili].copy()
    
    #We put 0 to the Port Not Selected
    first_clean["Port Important"] = first_clean["Port Important"].replace(port_delete, 0)
    
    # Per le porte messo -1 ai protocolli che non utilizzano la porta come ICMP 
    # per le porte meno conosciute messo 0 ed il resto lasciato il valore.
    
    first_clean["Label DSCP"] = dataframe["Label DSCP"]
    cols = first_clean.columns.tolist()
    cols.insert(0, cols.pop(cols.index('Label DSCP')))
    first_clean = first_clean.reindex(columns= cols)
    
    #variabili = ['Label DSCP', 'ds_field_ecn', 'length', 'Protocol', 'flag_df',
    #'flag_mf', 'fragment_offset', 'ttl', 'IP_SRC', 'IP_DST', 'Port Important']
    
    return first_clean




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
    categorical_features = [ "Protocol", "ds_field_ecn",
                            "Port Important"] # tolto flag_df e ds_field_ecn
    continuous_features = ["length", "ttl"]
    #continuous_features = []
    
    #Type of features:
    #Tolte fragment offset e flag_mf perché non inserite nella LDA 
    
    
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
    
    if len(continuous_features) > 0:
        dataset[continuous_features].describe()
        
        #Normalize the Continuous variables
        
        mms = MinMaxScaler()
        mms.fit(dataset[continuous_features])
        
        ### SAVE THE .fit Model
        filename = './Test_Classification/MinMaxScaler_fit_0403.sav'
        pickle.dump(mms, open(filename, 'wb'))
        
        #data_transformed = mms.transform(dataset[continuous_features])
        data_transformed = dataset[continuous_features]
        
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
    
    print("We continue to work, now on the categorical variables")
    print()
    
    #Convert dummy variables
    
    #Protocol: Protocol (Service Access Point (SAP) which indicates the type of transport 
    #           packet being carried (e.g. 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP).
    
    for col in categorical_features:
        #Inserito il drop first drop_first=True per problema della correlazione tra le k variabili
        
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
    
    #Per ora non ci concentriamo sulla cross validation
    #data_transformed.to_pickle("data_transformed_for_CrossValidation.pkl") 
    
    print(" Columns with the correct order : ")
    print(data_transformed.columns)
    print()
    
    return data_transformed



def dimensionality_reduction(dataframe ,n_comp = 3, method = [ "LDA"]):
    #method = ["PCA", "LDA"]
    for md in method:
        
        print("Now we work with this method : " + md)
        
        if md == "PCA":
    
            pca = PCA(n_components = n_comp, random_state=42)
            pca.fit(dataframe.iloc[:,1:])
            
            ########################################################################
            ########################## AGGIUNTO 10/09/2019##########################
            ### This part is added on September to verify the correctness to choose
            ### LDA as approach for the dimensionality reduction.
            
            #print("Saved the model using PCA")
            
            #filename = '../Test_Classification/PCA_fit.sav'
            #pickle.dump(pca, open(filename, 'wb'))
            ########################################################################
            
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
            
            print("Saved the model using LDA")
            
            
            
            #Inserire il salvataggi di lda per la VM
            #filename = '../Test_Classification/LDA_0430_fit.sav'
            #pickle.dump(lda, open(filename, 'wb'))
            
            import os
            cwd = os.getcwd()
            print(cwd)
            
            #Se prima Oversampling e poi LDA
            filename = '../Test_Classification/LDA_0403_fit.sav'
            
            #Se prima LDA e poi Oversampling
            #filename = './Test_Classification/LDA_0501_fit.sav'
            
            pickle.dump(lda, open(filename, 'wb'))
            
            #Here we specify only the x values not y
            lda_data = lda.transform(dataframe.iloc[:,1:].values)

            #The percentage of explained Variance
            pre_var = np.round(lda.explained_variance_ratio_ * 100 , decimals = 1)
            
            #labels = ["PC" + str(x) for x in range(1, len(pre_var)+1)]
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
        
        somma = 0
        for i in loading_scores.values:
            somma += abs(i)
        
        print()
        print(somma)
        print()
        
        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_1_' + md + '.csv')
        print()
        
        ##Component 2       
        
        print("Component2")
        print()
        
        if md == "PCA":
            loading_scores = pd.Series(pca.components_[1], index = dataframe.iloc[:,1:].columns )
        elif md == "LDA":
            loading_scores = pd.Series(lda.coef_[1], index = dataframe.iloc[:,1:].columns )
            
        print()
        somma = 0
        for i in loading_scores.values:
            somma += abs(i)
        
        print(somma)
        print()
            
        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_2_' + md + '.csv')
        print()
        
        #Component 3
        
        print("Component3")
        print()
        
        if md == "PCA":
            loading_scores = pd.Series(pca.components_[2], index = dataframe.iloc[:,1:].columns )
        elif md == "LDA":
            loading_scores = pd.Series(lda.coef_[2], index = dataframe.iloc[:,1:].columns )
        
        print()
        somma = 0
        for i in loading_scores.values:
            somma += abs(i)
        
        print(somma)
        print()


        sorted_loadng_scores = loading_scores.abs().sort_values(ascending=False)
        top_val = sorted_loadng_scores[0:].index.values
        print(loading_scores[top_val])
        print()
        print()
        loading_scores[top_val].to_csv('Influenza_Variabili_3_' + md + '.csv')
        print()
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
###############          COLOR and Class of Service          ##################
# =============================================================================
        '''
        #PER ORA COMMENTATO PERCHé DOBBIAMO VELOCIZZARE IL CODICE,
        #PROBLEMI DI MEMORIA
        
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
        '''
    #Osservando i valori ottenuti decidiamo di riprendere il dataframe 
    #generato utilizzando LDA
        
    return reduction_df


def error_Cluster(result, data_balanced ):
    
    ### Evaluate the clustering method for clustering ###
    
    ### L'idea è quella di pesare gli errori in modo tale da limitare
    ### gli errori per i quali la classe in cui è stato inserito 
    ### il pacchetto è completamente errata rispetto al tipo di servizio
    ### che aveva ed al seguente livello di priorità richiesto.
    
    
    cc ={'AF': "Black",
         'Critical voice RTP':"Red",
         'Network or Intenetwork control':"Blue",
         'Not Known':"Yellow",
         'best effort':"Green"}

    diz_class_occ = {}
    
    for elem in list(set(result)):
        diz_class_occ[elem] = [] 
        for pos in [x for x in range(len(result)) if result[x]==elem]:
            diz_class_occ[elem].append(data_balanced.iloc[pos,0])

    
    for i in diz_class_occ:
        #print()
        print("Cluster numero  " + str(i))
        print(Counter(diz_class_occ[i]))
        print()
    #print()
    
    error = 0 
    
    #Score distance
    
    score = {'best effort': 0,
             'Not Known': 1,
             'AF':2,
             'Critical voice RTP': 3,
             'Network or Intenetwork control': 4
             }   
        
    color_clutser = {}
    for i in diz_class_occ:
        #The condition of to be different from -1 is related to the case we are
        #clustering using the DBSCAN method
        if i != -1:
            #print()
            #print("# of Cluster is : " + str(i))
            diz = Counter(diz_class_occ[i])
            #print(diz)
            #print()
            a = max(diz.items(), key=operator.itemgetter(1))[0]
            #print(a)
            #print(cc[a])
            color_clutser[i] = [cc[a], a]
            
            for k in diz.keys():
                if k != a:
                    #print(k)
                    error += (abs(score[a] - score[k])) * diz[k]
                    #print((abs(score[a] - score[k])) * diz[k])
      
    return error, color_clutser

    

def Cluster(data, algo, peso = None):
    
    #We will use 2 possibilities K-Means and DBSCAN
    #The first one needs the number of cluster while the second one needs
    #about 2 parameters eps and min Pts.
    
    if algo == "K-Means":
        
        #Using the Elbow Method for having the optimal number of clusters
        print()
        print("Evaluating number of Clusters")
        print()
        
        #For each possible number of clusters we are gonna 
        #to compute the Sum of Squared Distance into each clusters 
        #then we plot the result thorough Elbow Method
        
        centers =[]
        inertia = []
        for i in range(1,9):
            kk = KMeans(n_clusters=i, init = 'k-means++', random_state = 0).fit(data)
            inertia.append(kk.inertia_)
            centers.append(i)
        print()
        
        
        print("Make the plot of the ELBOW Method")
        #Making the Plot of the Elbow Method
        plt.plot(centers, inertia, 'bx-')
        plt.xlabel('k')
        plt.ylabel('Sum_of_squared_distances')
        plt.title('Elbow Method For Optimal k')
        plt.savefig("Elbow Method.png", dpi = 150, figsize=(12,6))
        #plt.show()
        plt.close()
        
        #K-Means Algorithm
        
        #Here we set 5 cause we know that the number of classes analyzed
        kmeans = KMeans(n_clusters= 5, init = 'k-means++', random_state = 0)
        y_result = kmeans.fit_predict(data)
        
        centroidi = kmeans.cluster_centers_
        
        
    elif algo == "DBSCAN":
        
        #DBSCAN Algorithm

        nbrs = NearestNeighbors(n_neighbors= 5).fit(data)
        distances, indices = nbrs.kneighbors(data)
        print("The mean distance is about : " + str(np.mean(distances)))
        #np.median(distances)
        
        #dbscan = DBSCAN(eps= 0.0000000005, min_samples= 30700, metric="euclidean", 
        #                n_jobs = 1)
        
        #dbscan = DBSCAN(eps= 0.000005, min_samples= 700, metric="euclidean", n_jobs = -1)
        dbscan = DBSCAN(eps= 0.003, min_samples= 1000, metric="euclidean", n_jobs = -1)
       
        
        
        print(Counter(peso))
        print()
        
        y_result = dbscan.fit_predict(data,  sample_weight= peso)
        centroidi = "In DBSCAN there aren not Centroids"
        
        
    return y_result, centroidi
        

# =============================================================================
#                                     PLOT IN 2D   
# =============================================================================


def plot_2D_cluster(data, result, color_clutser, method, centroids):
    
    plt.figure(figsize=(10,5))
    
    for i in list(set((result))):
        if i != -1:
            plt.scatter(data[result == i, 0], data[result == i, 1], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
    
    #Centroid useful only with K-Means
    if method == "K-Means":
        plt.scatter(centroids[:, 0], centroids[:, 1], s = 300, c = 'r', marker='*', label = "Centroid")
    
    plt.title("2D - CLUSTERING with " + method)
#    plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
#    plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
    
    plt.xlabel("Ax_1")
    plt.ylabel("Ax_2")
    plt.legend(loc = "upper right")
    plt.savefig("Clustering_2D_with_" + method + ".png")
    plt.show()
    #plt.close()
    
    
# =============================================================================
#                                   PLOT IN 3D 
# =============================================================================

def plot_3D_cluster(data, result, color_clutser, method, centroids):
    
    fig = plt.figure(figsize=(10,5))
    ax = fig.add_subplot(111, projection='3d')

    for i in list(set((result))):
        if i != -1:
            ax.scatter(data[result == i, 0], data[result == i, 1], data[result == i, 2], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
        #else:
            #This part could be used for the DBSCAN plot classified as Noise        
            #ax.scatter(train[y_kmeans == i, 0], train[y_kmeans == i, 1], train[y_kmeans == i, 2], s = 50, c = "grey",  alpha = 0.3,label = "Noise")
    
            
    #ax.scatter(train[y_kmeans == 0, 0], train[y_kmeans == 0, 1], train[y_kmeans == 0, 2], s = 50, c = color_clutser[0][0],  alpha = 0.6,label = color_clutser[0][1])
    #ax.scatter(train[y_kmeans == 1, 0], train[y_kmeans == 1, 1], train[y_kmeans == 1, 2], s = 50, c = color_clutser[1][0],  alpha = 0.6, label = color_clutser[1][1])
    #ax.scatter(train[y_kmeans == 2, 0], train[y_kmeans == 2, 1], train[y_kmeans == 2, 2], s = 50, c = color_clutser[2][0],  alpha = 0.6, label = color_clutser[2][1])
    #ax.scatter(train[y_kmeans == 3, 0], train[y_kmeans == 3, 1], train[y_kmeans == 3, 2], s = 50, c = color_clutser[3][0],  alpha = 0.6, label = color_clutser[3][1])
    #ax.scatter(train[y_kmeans == 4, 0], train[y_kmeans == 4, 1], train[y_kmeans == 4, 2], s = 50, c = color_clutser[4][0],  alpha = 0.6, label = color_clutser[4][1])
    
    
    ax.set_title("3D - CLUSTERING with " + method)
#    ax.set_xlabel("PC1 - {0}%" .format(pre_var[0]))
#    ax.set_ylabel("PC2 - {0}%" .format(pre_var[1]))
#    ax.set_zlabel("PC3 - {0}%" .format(pre_var[2]))
    ax.set_xlabel("Ax_1")
    ax.set_ylabel("Ax_2")
    ax.set_zlabel("Ax_3")
    ax.dist = 10
    
    #Centroid useful only with K-Means
    if method == "K-Means":
        ax.scatter(centroids[:,0], centroids[:,1], centroids[:,2], s = 300, c = 'r', marker='*', label = 'Centroid')
    ax.legend( bbox_to_anchor=(0.20,0.75))
    plt.autoscale(enable=True, axis='x', tight=True)  
    plt.legend()  
    plt.savefig("Clustering_3D_with_" + method + ".png")
    plt.show()
    #plt.close()


def Silhouette_metrics_noPlot(start, stop, X, y, dataframe, data, sample_size):
    
    print()
    print("We are working with this sample size: " + str(sample_size))
    print()
    
    k_sample_result = []
    
    
    #Defyning the range of centroids to be considered
    #Passo singolo
    #range_n_clusters = list(range(start, stop + 1))
    #Passo da 5
    range_n_clusters = list(range(start, stop + 1,5))
    
    
    for n_clusters in range_n_clusters:
        
#        print()
#        print("Now we are evaluating this number of clusters: ")
#        print(str(n_clusters))
#        print()
        
        
        # Initialize the clusterer with n_clusters value and a random generator
        # seed of 10 for reproducibility.
        clusterer = KMeans(n_clusters=n_clusters, init = 'k-means++', random_state = 0)
        cluster_labels = clusterer.fit_predict(X)
        
#        print()
#        print("We are working with this number of clusters: " + str(n_clusters))
#        print()
                 
        #Inserita nelle variabili della funzione
        #sample_size = 70000
        
        media = []
        i = 0
        while i < 2:
            print(i)
            indices = np.random.RandomState().permutation(X.shape[0])[:sample_size]
            
            new_X, new_cluster_labels = X[indices], cluster_labels[indices]
            
#            print()
#            print("This is the Silhouette result : ")
#            print()
            
            # The silhouette_score gives the average value for all the samples.
            # This gives a perspective into the density and separation of the formed
            # clusters
            
            silhouette_avg = silhouette_score(new_X, new_cluster_labels)
#            print("For n_clusters =", n_clusters,
#                  "The average silhouette_score is :", silhouette_avg)
            
            media.append(silhouette_avg)
            i += 1
#        print()
#        print("media")
#        print(media)
#        print()
        
        silhouette_avg = sum(media)/len(media)
            
        #Saving the result of Silhouette in a dict 
        k_sample_result.append(silhouette_avg)
        
    return k_sample_result

    


def Silhouette_metrics(start, stop, X, y, dataframe, data, sample_size, new_prior = "False"):
    
    print()
    print("We are working with this sample size: " + str(sample_size))
    print()
    
    k_sample_result = []
    
    cc ={'AF': "Black",
         'Critical voice RTP':"Red",
         'Network or Intenetwork control':"Blue",
         'Not Known':"Yellow",
         'best effort':"Green"} 
    
    #Defyning the range of centroids to be considered
    range_n_clusters = list(range(start, stop + 1))
    
    
    for n_clusters in range_n_clusters:
        
        print()
        print("Now we are evaluating this number of clusters: ")
        print(str(n_clusters))
        print()
        
        # Create a subplot with 1 row and 2 columns
        #fig, (ax1, ax2) = plt.subplots(1, 2)
        
        fig = plt.figure()
        ax1 = fig.add_subplot(1, 2, 1)
        ax2 = fig.add_subplot(1, 2, 2, projection='3d')
        #33 -22
        fig.set_size_inches(18, 9)
    
        # The 1st subplot is the silhouette plot
        
        # The silhouette coefficient can assume a value from -1 to 1 but in 
        #this example all lie within [-0.1, 1]
        ax1.set_xlim([-0.05, 1])
        
        # The (n_clusters+1)*10 is for inserting blank space between silhouette
        # plots of individual clusters, to demarcate them clearly.
        
        #ax1.set_ylim([0, len(X) + (n_clusters + 1) * 10])
        
        #Al posto di X che ha tutte le osservazioni inserire il sottoCampione !!! 
        #Utilizzata la stessa grandezza del sample
        
        #ax1.set_ylim([0, 70000 + (n_clusters + 1) * 10])
        
        #era 50 ora mettiamo 100
        ax1.set_ylim([0, sample_size + (n_clusters + 1) * 260])
        
        # Initialize the clusterer with n_clusters value and a random generator
        # seed of 10 for reproducibility.
        clusterer = KMeans(n_clusters=n_clusters, init = 'k-means++', random_state = 0)
        cluster_labels = clusterer.fit_predict(X)
        
        print("Salvo Centroidi")
        centers = clusterer.cluster_centers_
        
        #To save centroids
        savetxt('data.csv', centers, delimiter=',')
        
        #Computing the Error Obtained previously
        
        print()
        err, s = error_Cluster(cluster_labels, dataframe)
        print("The total error with K == " + str(n_clusters) + " is : ")
        print(err)
        
        ##Correspondence for coloring
        
        diz_class_occ = {}
    
        for elem in list(set(cluster_labels)):
            diz_class_occ[elem] = [] 
            for pos in [x for x in range(len(cluster_labels)) if cluster_labels[x]==elem]:
                diz_class_occ[elem].append(dataframe.iloc[pos,0])
        
        print()
        print("We are working with this number of clusters: " + str(n_clusters))
        print()
        
        color_clutser = {}
        
        for i in diz_class_occ:
            #print()
            #print("# of Cluster is : " + str(i))
            diz = Counter(diz_class_occ[i])
            #print(diz)
            #print()
            a = max(diz.items(), key=operator.itemgetter(1))[0]
            #print(a)
            #print(cc[a])
            color_clutser[i] = [cc[a], a]
            
        #Inserita nelle variabili della funzione
        #sample_size = 70000
        indices = np.random.RandomState(seed=42).permutation(X.shape[0])[:sample_size]
        
        new_X, new_cluster_labels = X[indices], cluster_labels[indices]
        
        print()
        print("This is the Silhouette result : ")
        print()
        
        # The silhouette_score gives the average value for all the samples.
        # This gives a perspective into the density and separation of the formed
        # clusters
        
        silhouette_avg = silhouette_score(new_X, new_cluster_labels)
        print("For n_clusters =", n_clusters,
              "The average silhouette_score is :", silhouette_avg)
        
        #Saving the result of Silhouette in a dict 
        k_sample_result.append(silhouette_avg)
        
        # Compute the silhouette scores for each sample
        sample_silhouette_values = silhouette_samples(new_X, new_cluster_labels)
        
        #era 50 messo 100 per dare spazio
        y_lower = 260
        
        #Definire il dizionario dal quale poi possiamo stabilire
        #le differenti priorità
        diz_priority = {poss : [] for poss in cc.keys() }
        
        for i in range(n_clusters):

            # Aggregate Silhouette scores for samples belonging to
            # cluster i-th, and sort them
            ith_cluster_silhouette_values = \
                sample_silhouette_values[new_cluster_labels == i]
    
            ith_cluster_silhouette_values.sort()
            
            for ke , el in cc.items() :
                if el == color_clutser[i][0]:
                    try:
                        diz_priority[ke].append((i,sum(ith_cluster_silhouette_values)/len(ith_cluster_silhouette_values)))
                    except:
                        print("errore -- forse avviene per il sample troppo piccolo")
                        #Capire errore
                        diz_priority[ke].append((i, 0))
                        #print("ith_cluster_silhouette_values")
                        #print(ith_cluster_silhouette_values)
                        #print("ith_cluster_silhouette_values")
                        #print(ith_cluster_silhouette_values)
                        #print()
                        #print()
            
            size_cluster_i = ith_cluster_silhouette_values.shape[0]
            
            #print(size_cluster_i)
            
            y_upper = y_lower + size_cluster_i
            
            color = color_clutser[i][0]
            
            ax1.fill_betweenx(np.arange(y_lower, y_upper),
                              0, ith_cluster_silhouette_values,
                              facecolor=color, edgecolor=color, alpha=0.7)                
                

            ax1.text(-0.05, y_lower + 0.5 * size_cluster_i, str(i))
            
            # Compute the new y_lower for next plot
            #era 50 messo 100
            y_lower = y_upper + 260 # 10 for the 0 samples
        
        ax1.set_title("The silhouette plot for the various clusters", fontsize=15)
        ax1.set_xlabel("The silhouette coefficient values", fontsize= 13.5)
        ax1.set_ylabel("Cluster label", fontsize=13.5)
    
        # The vertical line for average silhouette score of all the values
        ax1.axvline(x=silhouette_avg, color="red", linestyle="--")
    
        ax1.set_yticks([])  # Clear the yaxis labels / ticks
        ax1.set_xticks([-0.1, 0, 0.2, 0.4, 0.6, 0.8, 1])
        
        # 2nd Plot showing the actual clusters formed
    
        # Labeling the clusters
        centers = clusterer.cluster_centers_
        # Draw white circles at cluster centers
        ax2.scatter(centers[:, 0], centers[:, 1],centers[:,2], marker='*',
                    c="lightyellow", s=150, edgecolor='k', label = "Centroids",alpha=0.8)
        
        #Plotting the centroids number
        #for i, c in enumerate(centers):
        #    ax2.scatter(c[0], c[1], c[2], marker='$%d$' % i, alpha=1,
        #                s=120, edgecolor='k')
        
        for i in list(set((cluster_labels))):
            #LABEL
            #ax2.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], data[cluster_labels == i, 2], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
            #No label
            ax2.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], data[cluster_labels == i, 2], s = 50, c = color_clutser[i][0],  alpha = 0.3)
            
            #ax2.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
        #ax2.scatter(train[cluster_labels == 1, 0], train[cluster_labels == 1, 1], train[cluster_labels == 1, 2], s = 50, c = color_clutser[1][0],  alpha = 0.3, label = color_clutser[1][1])
        #ax2.scatter(train[cluster_labels == 2, 0], train[cluster_labels == 2, 1], train[cluster_labels == 2, 2], s = 50, c = color_clutser[2][0],  alpha = 0.3, label = color_clutser[2][1])
        #ax2.scatter(train[cluster_labels == 3, 0], train[cluster_labels == 3, 1], train[cluster_labels == 3, 2], s = 50, c = color_clutser[3][0],  alpha = 0.3, label = color_clutser[3][1])
        #ax2.scatter(train[cluster_labels == 4, 0], train[cluster_labels == 4, 1], train[cluster_labels == 4, 2], s = 50, c = color_clutser[4][0],  alpha = 0.3, label = color_clutser[4][1])
    
    
        ax2.set_title("3D - CLUSTERING with K-Means",pad=20)
        ax2.set_xlabel("Ax_1")
        ax2.set_ylabel("Ax_2")
        ax2.set_zlabel("Ax_3")
        #ax2.dist = 10
    
        plt.suptitle(("Silhouette analysis for KMeans clustering on sample data "
                      "with n_clusters = %d" % n_clusters),
                     fontsize=14, fontweight='bold')
        #ax2.legend(bbox_to_anchor=(0.20,0.60))
        
        plt.autoscale(enable=True, axis='x', tight=True)
        plt.savefig("SilhoutteComparison_with" + str(n_clusters) + ".png",dpi = 250)
        plt.close()        
    #plt.show()
    
    #extract the legend
    

        fig = plt.figure(figsize=(30,17))
        ax = fig.add_subplot(111, projection='3d')
    
    # Labeling the clusters
        centers = clusterer.cluster_centers_
        # Draw white circles at cluster centers
        ax.scatter(centers[:, 0], centers[:, 1],centers[:,2], marker='*',
                    c="lightyellow", s=150, edgecolor='k', label = "Centroids",alpha=0.8)
        
        #Plotting the centroids number
        #for i, c in enumerate(centers):
        #    ax2.scatter(c[0], c[1], c[2], marker='$%d$' % i, alpha=1,
        #                s=120, edgecolor='k')
        
        for i in list(set((cluster_labels))):
            
            #LABEL
            ax.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], data[cluster_labels == i, 2], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
            #No label
            #ax.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], data[cluster_labels == i, 2], s = 50, c = color_clutser[i][0],  alpha = 0.3)
            
            #ax2.scatter(data[cluster_labels == i, 0], data[cluster_labels == i, 1], s = 50, c = color_clutser[i][0],  alpha = 0.3,label = color_clutser[i][1])
        #ax2.scatter(train[cluster_labels == 1, 0], train[cluster_labels == 1, 1], train[cluster_labels == 1, 2], s = 50, c = color_clutser[1][0],  alpha = 0.3, label = color_clutser[1][1])
        #ax2.scatter(train[cluster_labels == 2, 0], train[cluster_labels == 2, 1], train[cluster_labels == 2, 2], s = 50, c = color_clutser[2][0],  alpha = 0.3, label = color_clutser[2][1])
        #ax2.scatter(train[cluster_labels == 3, 0], train[cluster_labels == 3, 1], train[cluster_labels == 3, 2], s = 50, c = color_clutser[3][0],  alpha = 0.3, label = color_clutser[3][1])
        #ax2.scatter(train[cluster_labels == 4, 0], train[cluster_labels == 4, 1], train[cluster_labels == 4, 2], s = 50, c = color_clutser[4][0],  alpha = 0.3, label = color_clutser[4][1])
    
    
        ax.set_title("3D - CLUSTERING with K-Means")
        ax.set_xlabel("Ax_1")
        ax.set_ylabel("Ax_2")
        ax.set_zlabel("Ax_3")
        ax.dist = 10

        #ax.legend(loc="best", fontsize = "xx-small")
        ax.legend(bbox_to_anchor=(1, 1), loc=2, borderaxespad=0.)
        plt.savefig("legend.png", dpi = 250)
        plt.close()  
    
    
    
    #Algoritmo di base per definire come clusterizzare i dati
    if new_prior == "False":
        return k_sample_result
    
    #Ritorna il dizionario da cui possiamo stabilire la nuova priorità
    elif new_prior == "True":
        #Facciamo ritornare anche cluster labels perché al suo interno abbiamo le nuove labels
        return diz_priority, cluster_labels
        
        
    
        

