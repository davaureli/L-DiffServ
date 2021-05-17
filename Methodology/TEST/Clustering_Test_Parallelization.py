# -*- coding: utf-8 -*-
"""
Created on Wed Apr 24 16:35:04 2019

@author: Davide
"""

#Libraries
import glob
import pandas as pd
import numpy as np
#import random
import os
import time
from multiprocessing import Process, Manager

#Compute Min Distance between Packet and centroid

from numpy import genfromtxt
from sklearn.metrics import pairwise_distances_argmin_min
import timeit

from Functions import *
from Functions_Clustering import *


import itertools




def main():    
    
    # =============================================================================
    #                             Reading FILES
    # =============================================================================
    
    #VM
    name_folder = "Clustering"
    #Local
    #name_folder = "Clustering"
    
    print()
    print("This is the name folder " + name_folder)
    print()
    
    try:  
        os.mkdir(name_folder)
    except OSError:  
        print ("Creation of the directory %s failed" % name_folder)
    else:  
        print ("Successfully created the directory %s " % name_folder)
    
    #See all the possible .pcap files for working
    files = sorted(glob.glob('./shareCluster/shareCluster0403/*pkl'))

    print("Number of possible files to be choosen are:  " + str(len(files)) )
    print()
    
    
    
    #VM
    xx = list(range(0,1))
    #xx = list(range(0,8))
    #xx = [0]
    #Local
    #xx = list(range(0,len(files)))

    files = [ files[i] for i in xx]
    
    print("We'll work on these files: ")
    print()
    print(files)
    print()
    print("They are " + str(len(files)) + " files")
    
    
    start_time = time.time()
    
    manager = Manager()

    d = manager.dict()
    
    #index_to_delete = manager.dict()
    
    #Lista dei processi aperti
    lista_process = []
    
    for fl_name in files:
        #print(fl_name)
        p1 = Process(target= detect_indexToDelete, args=(fl_name,d,))
        lista_process.append(p1)
        p1.start() 
    #print(dizionario_check)
    for process in lista_process:
        process.join()

    print("--- %s seconds ---" % (time.time() - start_time))
    input()


    print("Extract Hash (Session) with more than 2 DSCP")
    hash_to_maintain = []
    conto = 0
    for k in d.keys():
        if len(d[k]) >= 2:
            conto += 1
        else:
            hash_to_maintain.append(k)
        
    print()
    print("Number of hash to delete")
    print(conto)
    print()
    print("Hash to maintain")
    print(len(hash_to_maintain))
    print()
    
    #Add new column for Marco Simulator. Mapping between DSCP and code
    
    diz_DSCP_codeSimulator = {0:["0"],
                              1:[str(i) for i in range(1,8)],
                              2:[str(i) for i in range(8,40)],
                              3:[str(i) for i in range(40,48)],
                              4:[str(i) for i in range(48,64)]}


    #Creation of an unique dataframe concatenating the selected ones
    df_new = pd.concat([pd.read_pickle(fp) for fp in files], ignore_index=True)
    
    label_for_simulation = []
    for i in df_new.index:
        dscp_label = df_new.iloc[i]["Label DSCP"]
        for key in diz_DSCP_codeSimulator:
            if dscp_label in diz_DSCP_codeSimulator[key]:
                label_for_simulation.append(key)
                
    print("Label Simulation")
    print(len(label_for_simulation))
    #input()
                
    df_new["Label Simulator"] = label_for_simulation
        
    
    df_new_for_txt = df_new[["time", 'IP_SRC', 'IP_DST', 'Protocol', "length", 
                             'src_port', 'dst_port', 'Label DSCP',"Label Simulator"]]
    #Select only some rows
    df_new_for_txt = df_new_for_txt.head(1000)
    
#    #Per Marco
#    print("Pacchetti osservati " + str(df_new_for_txt.shape[0]) )
#    
#    ### WRITE .TXT FILE
#    with open("Trace_0410_DSCP.txt", 'w+') as f:
#        f.write(df_new_for_txt.to_string(header = True, index = False, formatters = {"time":"{:.9f}".format} ))
#    ## WRITE .pickle Dataframe
#    df_new_for_txt.to_pickle('Trace_0508_DSCP.pkl')
    
    del df_new_for_txt
    
    
    print("Here we have created all the files for the simulation, used by Marco")
    #input()
    
    #input()
    
    print()
    print("This is the final DataFrame: ")
    print()
    print(df_new.head())
    print()
    #input()
    
    print()
    print("Number of packet will be analyzed are: " + str(df_new.shape[0]) + " packets")
    print()
    
    print()
    print()
    
    #print("Best Effort")
    #print(Counter(df_new[df_new["Label DSCP"] == "0"]["src_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"] == "0"]["dst_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"] == "0"]["Protocol"]).most_common(5))
    #print("Lunghezza pacchetti: ")
    #print(Counter(df_new[df_new["Label DSCP"] == "0"]["length"]).most_common(5))
    #
    #input()
    #
    #print()
    #print()
    #
    #print("AF")
    #label_AF = [ str(i) for i in range(8,40)]
    #print(Counter(df_new[df_new["Label DSCP"].isin(label_AF)]["src_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"].isin(label_AF)]["dst_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"].isin(label_AF)]["Protocol"]).most_common(5))
    #print("Lunghezza pacchetti: ")
    #print(Counter(df_new[df_new["Label DSCP"].isin(label_AF)]["length"]).most_common(5))
    #
    #input()
    #
    #print()
    #print()
    #
    #print("EF")
    #
#    label_EF = [ str(i) for i in range(40,48)]
#    print(Counter(df_new[df_new["Label DSCP"].isin(label_EF)]["src_port"]).most_common(5))
#    print(Counter(df_new[df_new["Label DSCP"].isin(label_EF)]["dst_port"]).most_common(5))
#    print(Counter(df_new[df_new["Label DSCP"].isin(label_EF)]["Protocol"]).most_common(5))
#    print("Lunghezza pacchetti: ")
#    print(Counter(df_new[df_new["Label DSCP"].isin(label_EF)]["length"]).most_common(5))
#    print("TTL")
#    print(Counter(df_new[df_new["Label DSCP"].isin(label_EF)]["ttl"]).most_common(5))
    #
    #input()
    #
    #print()
    #print()
    #
    #print("Network and Internetwork control")
    #print(Counter(df_new[df_new["Label DSCP"] == "48"]["src_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"] == "48"]["dst_port"]).most_common(5))
    #print(Counter(df_new[df_new["Label DSCP"] == "48"]["Protocol"]).most_common(5))
    #print("Lunghezza pacchetti: ")
    #print(Counter(df_new[df_new["Label DSCP"] == "48"]["length"]).most_common(5))
    #
    #input()
    
    
    # Cleaning part, dividing the Best Effort and Non Best Effort packets,
    # Now in the variables we are not considering the IP SRC and IP DST
    
    print()
    print("NOW START TO CLEAN THE BEST EFFORT DATAFRAME")
    print()
    
    #Extract only Best Effort
    df_BE = df_new[df_new["Label DSCP"] == "0"].copy()
    df_BE = Cleaning_for_Clustering(df_BE)
    
    print()
    print("NOW START TO CLEAN THE NON BEST EFFORT DATAFRAME")
    print()
    
    
    #Extract only Non Best Effort
    #df_new = df_new[df_new["Label DSCP"] != "0"]
    #    
    #    df_Non_BE = df_new[df_new["Label DSCP"] != "0"]
    #    df_Non_BE = Cleaning_for_Clustering(df_Non_BE)
    
    #print("We have finished to CLEAAAAN !!!!")
    #print("We delete df_new and create a new Datset")
    
    #Concatenate the 2 splitted Dataframes
    #    data_transformed  = pd.concat([df_BE, df_Non_BE], ignore_index=True)
    #    
    #    del df_BE,df_Non_BE
    
    
    label_Scavenger = [str(i) for i in range(1,8)]
    label_AF = [ str(i) for i in range(8,40)]
    label_EF = [ str(i) for i in range(40,48)]
    label_IntNetControl = [ str(i) for i in range(48,64)]
    
    
    #Observing the result we notice that we are losing the info about some priority classes:
    
    df_Scavenger = df_new[df_new["Label DSCP"].isin(label_Scavenger)]
    
    df_AF = df_new[df_new["Label DSCP"].isin(label_AF)]
    
    df_EF = df_new[df_new["Label DSCP"].isin(label_EF)]
    
    df_IntNetControl = df_new[df_new["Label DSCP"].isin(label_IntNetControl)]
    
    #print()
    #print("Starting Non Best Effort")
    #
    #input()
    df_Scavenger = Cleaning_for_Clustering(df_Scavenger)
    #print("Scavenger shape")
    #print(df_Scavenger.shape)
    #
    #input()
    df_AF = Cleaning_for_Clustering(df_AF)
    #print("AF shape")
    #print(df_AF.shape)
    #
    #input()
    df_EF = Cleaning_for_Clustering(df_EF)
    #print("EF shape")
    #print(df_EF.shape)
    #
    df_IntNetControl = Cleaning_for_Clustering(df_IntNetControl)
    #print("shape")
    #print(df_IntNetControl.shape)
    #
    #print("finish")
      
    
    #Concatenate the 2 splitted Dataframes
    #data_transformed  = pd.concat([df_BE, df_Scavenger, df_AF, df_EF, df_IntNetControl], ignore_index=True)   
    data_transformed  = pd.concat([df_BE, df_Scavenger, df_AF, df_EF, df_IntNetControl])
    data_transformed = data_transformed.sort_index()
    
    del df_BE, df_AF, df_EF, df_IntNetControl, df_Scavenger
    
    print("This is the occurrences of possible DSCP in our cleaned DataFrame")
    print()
    print(Counter(data_transformed["Label DSCP"]))
    print()
    print()
    
    ##Cambiato ora
    print(data_transformed.columns)
    
    data_attach_new_label = data_transformed.copy()
    
    
    print(data_transformed.shape)

    
#    for i in data_transformed.columns:
#        print(i)
#        input()
#        if "port" in i :
#            print(Counter(data_transformed[i]))
    
    
    # =============================================================================
    #                         DATA TRANSFORMATION
    # =============================================================================
    
    #We transform the categorical and Numerical variables using the function
    #Transform_Data
    
    data_transformed = Transform_data(data_transformed)
    
    print(data_transformed)
    input()
    
    print()
    print("Variabili Test")
    print(data_transformed.columns)
    #input()
    
    with open('columns_name_0403.pkl','rb') as f:
         variabili_scelte = pickle.load(f)
         
    print()
    print("Variabili Training")
    print(variabili_scelte)
    print()
    
    
    #L'idea è quella di inserire le colonne che abbiamo trovato nel training
    #ma non nel test. Ovviamente dobbiamo fare un check anche per quelle variabili presenti nel test
    #ma assenti nel training questo è da verificare !!!
    
    for col in variabili_scelte:
        if col not in list(data_transformed.columns):
            print("Questa variabile trovata nel TRAINING ma non trovata nel TEST : ")
            print(col)
            #input()
            #print()
            #Inserire una colonna con tutti zeri nel dataframe
            data_transformed[col] = 0
            
    ### Check sulle variabili presenti nel test ma non nel training
        
    not_training = []
    
    print()
    print("Variabili Test")
    print(data_transformed.columns)
    print()
        
    for col in list(data_transformed.columns):
        if col not in variabili_scelte:
            print("Questa variabile trovata nel TEST ma non trovata nel TRAINING: ")
            print(col)
            #input()
            not_training.append(col)
            #print()
            
    #Inserire il valore binario pari ad 1 nella colonna Port Important 0
    
    #Porte divise tra src e dst
    src_not_training = [col for col in not_training if "src" in col]
    dst_not_training = [col for col in not_training if "dst" in col]
    
    data_transformed[data_transformed[src_not_training] == 1]["src_port_0"] = 1
    data_transformed[data_transformed[dst_not_training] == 1]["dst_port_0"] = 1
    
    #Porte Unificate nella porta fondamentale        
    #data_transformed[data_transformed[not_training] == 1]["Port Important_0"] = 1
    
    #Eliminare le colonne delle porte che non sono state trovate fondamentali 
    #nel training ma sono presenti nel Test
    data_transformed.drop(not_training, axis=1, inplace=True)
    
    print()
    print("Finito il check")
    print()
    print("Counter")
    print(Counter(list(data_transformed.columns) + list(variabili_scelte)))

    #input()
    
    #We transform the Label of DSCP from Decimal value to the class string about the
    #service
    label = []
    
    #for i in data_transformed["Label DSCP"]:
    #    if int(i) == 0:
    #        label.append("best effort")
    #    elif int(i)>0 and int(i)<8:
    #        label.append("Not Known")
    #    elif int(i)>=8 and int(i)<16:
    #        label.append("Priority")
    #    elif int(i)>=16 and int(i)<24:
    #        label.append("Immediate")
    #    elif int(i)>=24 and int(i)<32:
    #        label.append("Flash Voice")
    #    elif int(i)>=32 and int(i)<40:
    #        label.append("Falsh Override")
    #    elif int(i)>=40 and int(i)<=47:
    #        label.append("Critical voice RTP")
    #    else:
    #        label.append("Network or Intenetwork control")
    
    
        
    #Saving the actual decimal values of the DSCP Column
    dscp_decimal_value = data_transformed["Label DSCP"].copy() 
    
    
    print()
    print("Transform the DSCP decimal Values into class string about the Service")
    print()
    
    for i in data_transformed["Label DSCP"]:
        if int(i) == 0:
            label.append("best effort")
        elif int(i)>0 and int(i)<8:
            label.append("Not Known")
        elif int(i)>=8 and int(i)<40:
            label.append("AF")
        elif int(i)>=40 and int(i)<=47:
            label.append("Critical voice RTP")
        else:
            label.append("Network or Intenetwork control")
    
    #Replacing the old values with the new ones
    data_transformed["Label DSCP"] = label
    
    #If we want to mantain the actual DiffServ classification 
    #data_transformed["Label DSCP"] = dscp_decimal_value
    
    print()
    print("New Dataframe: ")
    print(data_transformed.head())
    print()
    print("New Label Occurrences")
    print(Counter(data_transformed["Label DSCP"]))
    print()
    
    
    
    print(data_transformed.head())
    print()
    print(data_transformed.columns)
    input()
    
    #data_transformed = data_transformed[data_transformed["Label DSCP"] == "Critical voice RTP"]
    #data_transformed = data_transformed.rename(columns = {"Protocol_1":"a"}) 
    data_transformed = data_transformed[variabili_scelte]
    data_transformed.to_pickle("Dung2.pkl")
    
    print(data_transformed.head())
    
       
    #### Applicare LDA senza aver modificato le variabili
    
    # load the model from disk
    loaded_model = pickle.load(open("LDA_0403_fit.sav", 'rb'))

    lda_data = loaded_model.transform(data_transformed.iloc[:,1:].values)

    #print(data_transformed)
    
    labels = ["LD" + str(x) for x in range(1, 4)]
    
    reduction_df = pd.DataFrame(lda_data, columns = labels)            
    
    
    #Adding the Label values
    
    reduction_df["Label DSCP"] = data_transformed["Label DSCP"].values
    cols = reduction_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index("Label DSCP")))
    reduction_df = reduction_df.reindex(columns= cols)
    
    print()
    print("This is the obtained new Dataframe with the new Components")
    print()
    print(reduction_df.head())
    print()
      
    
    # =============================================================================
    #                               CLASSIFICATION PART
    # =============================================================================
    
    
    #Prima classificazione con i centroidi
    print("Prima metodologia di classificazione")
    

    
    #Open the new priority created by the K-Means
    with open('../simulator/Priority0403.pkl', 'rb') as handle:
        priority = pickle.load(handle)
        
    print("Priority")
    print(priority)
    print()
    
    centroidi = genfromtxt('centroids_data_0403.csv', delimiter=',')
    
    print("INIZIO LAVORO CENTROIDI")
    #Pacchetti creati fittiziamente sono LDA1 LDA2 LDA3
    punti_spazio = reduction_df.iloc[:,1:]
    
    
    def calcolo_nuovaClasse(centroidi, dati):
        
        closet= pairwise_distances_argmin_min(dati, centroidi)
        
        return closet[0]
        
    print()
    print(centroidi)
    print()
    
    start = timeit.default_timer()
    
    a = calcolo_nuovaClasse(centroidi, punti_spazio)
    
    stop = timeit.default_timer()
    
    print('Time: ', stop - start)
    
    print("Risultato ottenuto con calcolo dei centroidi")
    print(len(list(a)))
    
    #Prima classificazione con i centroidi
    print(Counter(a))
    print()
    
    '''
    ############ Classify the new packets according to the selected algorithm
    
    ### Download what we have saved
    print("Loading the model")
    # load the model from disk
    
    #Iniziamo a prendere i tempi
    start = time.time()
    
    filename = "classification_model_0403.sav"
    loaded_model = pickle.load(open(filename, 'rb'))
    
    #print()
    #print("Apply the model")
    
    #For now we have classified elements only considering the first 2 components
    result = loaded_model.predict(reduction_df.iloc[:,1:])
    
    
    end = time.time()
    print("TEMPO DI ESECUZIONE Random Forest")
    print(end - start)
    
    print(len(result))
    
    print()
    print("Add the new classification according to our analysis")
    
    
    reduction_df.insert(1, "New DSCP", result)
    
    print()
    print("This is our new dataframe: ")
    
    print(reduction_df.head())
    
    ##Dobbiamo salvar il dataframe in modo tale da costruire le informazioni con 
    #il codice del simulatore.
    
    #Creation of an unique dataframe concatenating the selected ones
    dataframe_Simulation = pd.concat([reduction_df[["Label DSCP", "New DSCP"]], columns_for_simulation], axis = 1)
    
    print("Finally we have merged the new dataframe with the columns useful for SIMULATION !!!")
    print()
    print("This is our final result !")
    print()
    print(dataframe_Simulation.head())
    print()
    
    print()
    print(Counter(reduction_df["New DSCP"]))
    print()
    
    print()
    print("Save the Datframe in the Simulation Folder")
    
    
    #Using LDA
    #dataframe_Simulation.to_pickle("../../simulator/dataframe_Simulation0415.pkl")
    #Using PCA
    dataframe_Simulation.to_pickle("../../simulator/dataframe_SimulationNew_0403.pkl")
    print()
    
    '''
    
    #Salvare il DataFrame
    
    #data_transformed["New DSCP"] = dataframe_Simulation["New DSCP"]
    
    #Add label to the dataframe with LDA
    reduction_df["New DSCP"] = a
    reduction_df.to_pickle("../simulator/dataset0403_dettagliato.pkl")
    
    #Add label to the dataframe with all info
    data_attach_new_label["New DSCP"] = a
    data_attach_new_label.to_pickle("../simulator/preghiamo_0403.pkl")
    
    #Correct Datframe where we can have even the hash function
    #data_attach_new_label["New DSCP"] = a
    #data_attach_new_label.to_pickle("../../simulator/dataset0403_dettagliato.pkl")
    
    
    for value in set(reduction_df["New DSCP"]):
        print(value)
        print(Counter(reduction_df[reduction_df["New DSCP"] == value]["Label DSCP"]))
        print()
        input()
    
    #df_new["New DSCP"] = a
    #df_new.to_pickle("../../simulator/dataset0403_dettagliato.pkl")
    
    print(data_transformed.columns)
    
    #Trasformare la colonna della Label Aggiunta
    
    diz_classeDSCP_labelCluster = {}
    for k,elem in priority.items():
        for i in range(len(elem)):
            diz_classeDSCP_labelCluster[elem[i][0]] = k
    print()
    print()
    print(diz_classeDSCP_labelCluster)
    input()
    
    for i in diz_classeDSCP_labelCluster:
        reduction_df["New DSCP"].replace(i,diz_classeDSCP_labelCluster[i], inplace = True)
        
    
    print(reduction_df["New DSCP"])
    input()
        
        
    #CONFUSION MATRIX RESULT

    y_actu = pd.Series(reduction_df["Label DSCP"].values, name='Actual')
    y_pred = pd.Series(reduction_df["New DSCP"].values, name='Predicted')
    df_confusion = pd.crosstab(y_actu, y_pred)
    
    df_confusion = pd.crosstab(y_actu, y_pred, rownames=['Actual'], colnames=['Predicted'], margins=True)
    
    #Fare il check se sono presenti tutte le classi di servizio 
    for k in set(reduction_df["Label DSCP"]):
        if k not in df_confusion:
            df_confusion.insert(loc=0, column=k, value="")
            df_confusion[k] = 0
    
    
    #Reorder columns
    df_confusion = df_confusion[['best effort','Not Known','AF', 'Critical voice RTP', 'Network or Intenetwork control', 'All']]
    #Reorder index
    df_confusion =  df_confusion.reindex(['best effort','Not Known','AF', 'Critical voice RTP', 'Network or Intenetwork control', 'All'])
    
    #Rename Index
    df_confusion.rename(index={'best effort': 'BE', 'Not Known':"Scavenger", 'AF':"AF", 
                               'Critical voice RTP':"EF", 
                               "Network or Intenetwork control":"NIC"}, inplace = True)
        
    #Rename columns
    df_confusion.rename(columns={'best effort': 'BE', 'Not Known':"Scavenger", 
                                 'AF':"AF", 'Critical voice RTP':"EF",
                                 "Network or Intenetwork control":"NIC"}, inplace = True)
    
    
    df_confusion.to_pickle("Mascherina.pkl")
    print("Salvato")
    print(df_confusion)
    input()

    #Normalization of the results
    final_df = df_confusion.div(df_confusion["All"], axis='index')
    
    print(final_df)
    input()
    
    import matplotlib.pyplot as plt
#    def plot_confusion_matrix(df_confusion, title='Confusion matrix', cmap=plt.cm.gray_r):
#        
#        plt.figure(figsize=(30,20))
#        
#        plt.matshow(df_confusion, cmap=cmap) # imshow
#        #plt.title(title)
#        plt.colorbar()
#        tick_marks = np.arange(len(df_confusion.columns))
#        plt.xticks(tick_marks, df_confusion.columns, rotation=45)
#        plt.yticks(tick_marks, df_confusion.index)
#        #plt.tight_layout()
#        plt.ylabel(df_confusion.index.name)
#        plt.xlabel(df_confusion.columns.name)
#        #plt.savefig("Confusion Matrix result", dpi = 250)
#        plt.savefig("prova", dpi = 250)
#        plt.show
#        
     
    #Plot Confusion Matrix
    #plot_confusion_matrix(final_df.iloc[:-1,:-1])
    
    cm = final_df.iloc[:-1,:-1]
    
    def plot_confusion_matrix(cm, classes, title='Confusion matrix', cmap=plt.cm.Blues):
        
        """
        This function prints and plots the confusion matrix.
        Normalization can be applied by setting `normalize=True`.
        """
        
        #plt.figure(figsize=(10,8))
        
        plt.imshow(cm, interpolation='nearest', cmap=cmap)
        plt.title(title)
        plt.colorbar()
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes, rotation=45)
        plt.yticks(tick_marks, classes)
    
        thresh = cm.max() / 2.
        print(thresh)
        for i, j in itertools.product(range(len(list(cm.index.values))), range(len(list(cm.columns.values)))):
         plt.text(j, i, round(cm.loc[list(cm.index.values)[i], list(cm.columns.values)[j]],2),
                  horizontalalignment="center", 
                  color="white" if sum(cm.loc[list(cm.index.values)[i], list(cm.columns.values)[j]] > thresh) == cm.shape[0] else "black")
        plt.tight_layout()
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        plt.savefig("ConfusionMatrixCorrect_compleanno_mini", dpi = 250,bbox_inches="tight")
        
    #Plot 
    
    class_names = cm.columns
    
    plt.figure()
    plot_confusion_matrix(cm, classes=class_names, 
                  title='')
    #plt.show()
           
    
    
    #ANALISI RISULTATI

if __name__ == '__main__':
    main()
