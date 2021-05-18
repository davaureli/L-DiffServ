# -*- coding: utf-8 -*-
"""
Created on Wed Apr 24 16:35:04 2019

@author: Davide
"""

#Libraries
import glob
import pandas as pd
import random
import os
import time
import operator
from tqdm import tqdm

from multiprocessing import Process, Manager

#For plotting the Histogram and Density
import seaborn as sns

from Functions import *

#Differentiation with only one port
#from Functions_Clustering import *
from Functions_Clustering_Differentiation_Port import *

#Balancing Dataset
#from imblearn.combine import SMOTEENN
from imblearn.over_sampling import SMOTE
#from imblearn.under_sampling import RepeatedEditedNearestNeighbours



#Work & Clean

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

print("Starting Analysis")

#VM
#dizionario_check, indexDelete = detect_indexToDelete(df_new, final_dict_HASH)
#Local
#dizionario_check, indexDelete = detect_indexToDelete(df_new)


# Function to analyze singular DSCP class
#Write result in a file
def infoForClassesDSCP(dataframe, number_obs, dscp_class, name_folder_cwd):
    
    variable_check = ["src_port", "dst_port", "Protocol", "length","ds_field_ecn"]
    print("Working with: " + dscp_class)
    
    #Option "a" in the writing file append elements 
    
    with open(name_folder_cwd +"/file_result.txt", "a") as f:
            f.write("Lavoriamo con " + dscp_class)
            
            for var in variable_check:
                print(var)
                
                values_obtained = Counter(dataframe[var]).most_common(number_obs)
                
                f.write("\n")
                f.write(var + "   " + " Occurrences")
                f.write("\n")
                for k,v in  values_obtained:
                    f.write( "{}       {}\n".format(k,v) )
                    
                print(values_obtained)
                

                f.write("\n")
                f.write("\n")
                
                if var == "length":
                    
                    diz = dataframe[var].values
                    
                    #Save length of packet
                    with open(name_folder_cwd + "/" + dscp_class + '_pckLength.pkl', 'wb') as handle:
                        pickle.dump(diz, handle, protocol=pickle.HIGHEST_PROTOCOL)
    

                elif var == "src_port":

                    
                    srcport = dataframe[var].values
                    
                    #Save length of packet
                    with open(name_folder_cwd + "/" + dscp_class + '_srcPort.pkl', 'wb') as handle:
                        pickle.dump(srcport, handle, protocol=pickle.HIGHEST_PROTOCOL)


                elif var == "dst_port":
   
                    dstport = dataframe[var].values
                    
                    #Save length of packet
                    with open(name_folder_cwd + "/" + dscp_class + '_dstPort.pkl', 'wb') as handle:
                        pickle.dump(dstport, handle, protocol=pickle.HIGHEST_PROTOCOL)
   
def extractIndexToDelete(data, columns_observed, lista_index):
    
    DF = data[columns_observed]
    index_to_delete = DF[DF.apply(lambda x: min(x) == max(x), 1)].index
    print("Indici")
    print(len(index_to_delete))
    for i in index_to_delete:
        lista_index.append(i)




    
def main():    
    
    # =============================================================================
    #                             Reading FILES
    # =============================================================================
    
    #VM
    name_folder = "Clustering_Prova"
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
    #files = sorted(glob.glob('./shareCluster/*pkl'))
    files = sorted(glob.glob('./shareCluster0403/*pkl'))

    print("Number of possible files to be choosen are:  " + str(len(files)) )
    print()
    
    
    #VM
    #xx = list(range(0,3))
    xx = list(range(0,len(files)))
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
    
    #Creation of an unique dataframe concatenating the selected ones, with a new index
    df_new = pd.concat([pd.read_pickle(fp) for fp in files], ignore_index=True)
    
    print("Start Dimension of the concatenate Dataframe")
    print()
    print(df_new.shape)
    print()
    
    print("Total Number of Hash")
    print(len(set(df_new["Hash"])))
    
            
    df_new = df_new[df_new['Hash'].isin(hash_to_maintain)]
    
    print("New Dimension of the concatenate Dataframe")
    print()
    print(df_new.shape)
    print()
    
    
    
    print()
    print(Counter(df_new["Label DSCP"]))
    print("Controllo di Porte e Protocolli")
    print()
    
    print("Analisi delle singole classi: ")
    
    print()
    print()

#Commentare da qui
    
    #dataframe, number_obs, dscp_class
    infoForClassesDSCP(df_new[df_new["Label DSCP"] == "0"], 15, "Best Effort", name_folder)
    
    label_Scavenger = [str(i) for i in range(1,8)]
    infoForClassesDSCP(df_new[df_new["Label DSCP"].isin(label_Scavenger)], 15, "Scavenger",name_folder)
    
    label_AF = [ str(i) for i in range(8,40)]
    infoForClassesDSCP(df_new[df_new["Label DSCP"].isin(label_AF)], 15, "AF",name_folder)
    
    label_EF = [ str(i) for i in range(40,48)]
    infoForClassesDSCP(df_new[df_new["Label DSCP"].isin(label_EF)], 15, "EF",name_folder)
    
    infoForClassesDSCP(df_new[df_new["Label DSCP"] == "48"], 15, "Network e Internetwork Control",name_folder)
    

#Commentare fino a qui
    
#    print("Pacchetti BE con porta 80 src e dst")
#    print(df_new[(df_new["Label DSCP"] == "0") & (df_new["src_port"] == "80") & (df_new["dst_port"] == "80")].shape)
#    print("Pacchetti BE con porta 443 src e dst")
#    print(df_new[(df_new["Label DSCP"] == "0") & (df_new["src_port"] == "443") & (df_new["dst_port"] == "443")].shape)
#    input()
#    
#    print()
#    print("Osserviamo pacchetti porta 80 differenze tra BE e AF")
#    print("be")
#    print(Counter(df_new[(df_new["Label DSCP"] == "0") & (df_new["dst_port"] == "80")]["length"]).most_common(5))
#    print("af")
#    print(Counter(df_new[(df_new["Label DSCP"].isin(label_AF)) & (df_new["dst_port"] == "80")]["length"]).most_common(5))
#    
    
# =============================================================================


   
##     
##     # Nuova Parte di Analisi e osservazione della posizione dei pacchetti:
#
#    print()
#    print("NOW START TO CLEAN THE BEST EFFORT and NON BEST EFFORT DATAFRAME")
#    print()
#    
#    #Extract only Best Effort
#    df_BE = df_new[df_new["Label DSCP"] == "0"].copy()
#    df_Non_BE = df_new[df_new["Label DSCP"] != "0"].copy()
#    
#    del df_new
#    
#    
#    start_time = time.time()
#
#    df_BE = Cleaning_for_Clustering(df_BE)
#    df_Non_BE = Cleaning_for_Clustering(df_Non_BE)    
#
#    print("--- %s seconds ---" % (time.time() - start_time))
#
#    
#    #Concatenate the 2 splitted Dataframes
#    data_transformed  = pd.concat([df_BE, df_Non_BE], ignore_index=True)
#    
#    del df_BE,df_Non_BE
#    
#    print()
#    print("This is the occurrences of possible DSCP in our cleaned DataFrame")
#    print()
#    print(Counter(data_transformed["Label DSCP"]))
#    print()
#    
#    print("Now we begin the Data Transformation")
#    print()
#    
#    data_transformed = Transform_data(data_transformed)
#
#    
#    label = []
#
#    
#    #Saving the actual decimal values of the DSCP Column
#    dscp_decimal_value = data_transformed["Label DSCP"].copy() 
#    
#    print()
#    print("Transform the DSCP decimal Values into class string about the Service")
#    print()
#    
#    for i in data_transformed["Label DSCP"]:
#        if int(i) == 0:
#            label.append("best effort")
#        elif int(i)>0 and int(i)<8:
#            label.append("Not Known")
#        elif int(i)>=8 and int(i)<40:
#            label.append("AF")
#        elif int(i)>=40 and int(i)<=47:
#            label.append("Critical voice RTP")
#        else:
#            label.append("Network or Intenetwork control")
#    
#    #Replacing the old values with the new ones
#    data_transformed["Label DSCP"] = label
#    
#    data_transformed.to_pickle("./coronavirus.pkl")
#    
#    print("DIMENSIONALITY REDUCTIONNN")
#    df  = dimensionality_reduction(dataframe = data_transformed)
#    
#    print("df")
#    print(df)
#    
#    #df.to_pickle("./coronavirus.pkl")
#    
    
# =============================================================================

    print()
    print("Number of packets will be analyzed is: " + str(df_new.shape[0]) + " packets")
    print()
    

    #Commentata questa parte -- Nuove Prove
    print("Cancelliamo i duplicati")
    df_new.drop_duplicates(inplace = True)
    print(df_new.shape)
    #Togliere commenti da questa parte --- Ricordare
    
    #Save Dataframe to count sessions number and typology
    df_new.to_pickle("data_0403_sessioni.pkl")
    
    print("Dataset Salvato !!!")
    input()

    
    '''
    #Statistical plot observing the distrbution of Packet Length
    
    print()
    print("Now we can see the Distribution of Packet length the most important numerical feature")
    print()
    
    
    
    
    #Plot of Packet Length with the density
    
    #Select the column with the variable length and transform it into a numpy array
    std_length = np.array(df_new["length"])
    #plt.hist(std_length)
    #Standard Deviation
    #print(np.std(std_length))
    print("Make the Plot")
    plt.figure(figsize=(9,5))
    fig = sns.distplot(std_length, hist = True, kde = True, rug=True, 
                 bins = 20).set(xlim=(0, max(std_length)))
    
    plt.xlabel("Packet Length",fontsize=10.5)
    plt.ylabel("Density",fontsize=10.5)
    #plt.title('Density Plot and Histogram of Packet Length', fontsize=14)
    plt.savefig(name_folder + "/Density_Histogram_Length.png", dpi = 250)
    plt.show(fig)
    
    print()
    print("Saved the plot")
    print()
    
    '''
    
    # Cleaning part, dividing the Best Effort and Non Best Effort packets,
    # For the variables we are not considering the IP SRC and IP DST
    
    print()
    print("NOW START TO CLEAN THE BEST EFFORT DATAFRAME")
    print()
    
    #Extract only Best Effort
    df_BE = df_new[df_new["Label DSCP"] == "0"].copy()
    df_BE = Cleaning_for_Clustering(df_BE)
    
    #input()
    
    print()
    print("NOW START TO CLEAN THE NON BEST EFFORT DATAFRAME")
    print()
    
    
    #Extract only Non Best Effort
    df_new = df_new[df_new["Label DSCP"] != "0"]
    
    
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
    
    del df_new
    print()
    
    print("Starting Non Best Effort")
    
    df_Scavenger = Cleaning_for_Clustering(df_Scavenger)
    
    #input()
    
    df_AF = Cleaning_for_Clustering(df_AF)
    
    #input()
    
    df_EF = Cleaning_for_Clustering(df_EF)
    
    #input()
    
    df_IntNetControl = Cleaning_for_Clustering(df_IntNetControl)
    
    print("Finish")
    
    #Concatenate the 2 splitted Dataframes
    data_transformed  = pd.concat([df_BE, df_Scavenger, df_AF, df_EF, df_IntNetControl], ignore_index=True)   
    
    
    print()
    print(Counter(data_transformed["Label DSCP"]))
    
    #input()

    
    print()
    print("This is the occurrences of possible DSCP in our cleaned DataFrame")
    print()
    print(Counter(data_transformed["Label DSCP"]))
    print()
    
    
    print()
    print("Now we begin the Data Transformation")
    print()
    
    #Delete Duplicates
    
    #Commentata questa parte -- Nuove Prove
#    print("Cancelliamo i duplicati")
#    data_transformed.drop_duplicates(inplace = True)
#    data_transformed = data_transformed.reset_index(drop=True)
#    print(data_transformed.shape)
#    print(Counter(data_transformed["Label DSCP"]))
#    print()
#    input()
    #Togliere commenti da questa parte --- Ricordare
    
    
    # =============================================================================
    #                         DATA TRANSFORMATION
    # =============================================================================
    
    #We transform the categorical and Numerical variables using the function
    #Transform_Data    
    
    data_transformed = Transform_data(data_transformed)
    #print(data_transformed.columns)
    mylist = list(data_transformed.columns)
    input()
    #Save in a pickle format the columns name for the
    #Ground Truth when we will take the new trace for test it.
    
    with open('./Test_Classification/columns_name_0403.pkl', 'wb') as f:
        pickle.dump(mylist, f)
    
    print()

    
    #We transform the Label of DSCP from Decimal value to the class string about the
    #service. We need to consider the AF as a unify group cause there are always few observation.
    #for this class of service.
    
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
    
    print()
    print("New Dataframe: ")
    print(data_transformed.head())
    print()
    print("New Label Occurrences")
    print(Counter(data_transformed["Label DSCP"]))
    print()
    
#    for ll in list(set(data_transformed["Label DSCP"])):
#        check = data_transformed[data_transformed["Label DSCP"] == ll]
#        for col in check.columns:
#            print()
#            print("Work with: " + str(ll))
#            print(col)
#            print(Counter(check[col]))
#            print()
#            print()
#            
#            input()
        
    
    # =============================================================================
    #                     Oversampling Part - BALANCING THE DATASET
    # =============================================================================
    
    print()
    print("Now we have to REBALANCE the Dataset")
    print()
    
    #Features X and Label y
    X = data_transformed.iloc[:, 1:].values
    y = data_transformed.iloc[:, 0].values
    
    print()
    print("Distribution of starting y:")
    print(sorted(Counter(y).items()))
    print()
    
    print("Number of best effort obesrvation is :")
    daje = Counter(y).items()
    for ele in daje:
        if ele[0] == "best effort":
            number_of_smote = ele[1]
    
    #The same number of observation between Best Effort and the other classes
    print(number_of_smote)
    print()
    
    
    #print("NOW START UNDERSAMPLING:")
    #print()
    #print("Using ENN")
    #print()
    
    #start = time.time()
    
    #Local
    #renn = RepeatedEditedNearestNeighbours(sampling_strategy = 'majority', random_state = 0,  n_neighbors = 700, n_jobs= 2 , max_iter = 250)
    #VM
    #renn = RepeatedEditedNearestNeighbours(sampling_strategy = ["best effort", "Not Known"], random_state = 0,  n_neighbors = 50000, n_jobs= -1 )
    
    #Transform the occurrences of train X and y
    #X_under_resampled, y_under_resampled = renn.fit_resample(X, y)
    
    #end = time.time()
    #print(end - start)
    #print()
      
    #print("After undersampling this is the y distribution: ")
    #print(sorted(Counter(y_under_resampled).items()))
    #print()
    
    print("NOW START OVERSAMPLING:")    
    print()
    print("Using SMOTE")
    print()
    
    #Local
    #smote = SMOTE(random_state=0, k_neighbors= 1,  n_jobs= 4 )
    #VM
    smote = SMOTE(random_state = 42, k_neighbors= 3, 
                  sampling_strategy = {"Critical voice RTP" : number_of_smote , "AF": number_of_smote, 
                                       "Network or Intenetwork control":number_of_smote, 'Not Known':number_of_smote })
    
    
    #Resample about X and y
    #X_resampled, y_resampled = smote_enn.fit_resample(X_under_resampled, y_under_resampled)
    #X_resampled, y_resampled = smote.fit_resample(X_under_resampled, y_under_resampled)
    
    #Without Undersampling
    X_resampled, y_resampled = smote.fit_resample(X, y)
    
    del X,y
    
    print()
    print("Final Distribution after Undersampling & Oversampling: ")
    print(sorted(Counter(y_resampled).items()))
    print()
    
    #Creating the DataFrame
    
    #Size of number of sample
    row = X_resampled.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    y_resampled = np.reshape(y_resampled,(row,1))
    
    #Concatenating the X and y into a numpy array
    data = np.concatenate((y_resampled, X_resampled), axis=1)
    
    del X_resampled,y_resampled
    
    #Columns for the DataFrame
    col = data_transformed.columns
    
    #FINAL BALANCED Dataframe
    df_balanced_train = pd.DataFrame(data = data, columns = col)
    
    del data
    
    ##Remember we have a PROBLEM after the SMOTE : WARNING !!!
    
    #Transform the Synthetic sample created by SMOTE into real sample, 
    #cause the categorical variable have a non integer value, for instance,
    # Protocol now has a non an integer value between 0 and 1 but it does 
    #not make sense. Our idea is to approximate values.
    
    print()
    print("Cleaning the SMOOTE Result")
    
    colonne_cat = []
    for col in list(df_balanced_train.columns):
        if col != "Label DSCP" and col != "length" and col != "ttl":
            colonne_cat.append(col)
    
    print()
    print("We approximate these columns: ")
    print(colonne_cat)
    print()
    
    #Approximating the column selected
    df_balanced_train[colonne_cat] = np.round(df_balanced_train[colonne_cat].astype(np.double),0)
    
    #Verifying the result after the approximation we will have only values 
    # 0 or 1
    
    ## Final Control Commenato###
    
#    print("Final Control")
#    print()
#    for i in colonne_cat:
#        print(Counter(df_balanced_train[i]))
#    print()
    
    
#    for ll in list(set(df_balanced_train["Label DSCP"])):
#        check = df_balanced_train[df_balanced_train["Label DSCP"] == ll]
#        for col in check.columns:
#            print()
#            print("Work with: " + str(ll))
#            print(col)
#            print(Counter(check[col]))
#            print()
#            print()
#            
#            input()
            
    print("Final check about 0 in the Ports ...")
    print(df_balanced_train.columns)
    
    columns_src_port = []
    columns_dst_port = []
    columns_protocol = []
    
    for elem in df_balanced_train.columns:
        if "src_port" in elem :
            columns_src_port.append(elem)
        elif "Protocol" in elem:
            columns_dst_port.append(elem)
        elif "dst_port" in elem:
            columns_protocol.append(elem)
            
    print("Cleaning packet without info")
    print()
    print(columns_src_port)
    print(columns_dst_port)
    print(columns_protocol)
    #input()
    
    total_columns = [columns_src_port, columns_dst_port, columns_protocol]
    
    manager = Manager()

    list_Index_To_Delete = manager.list()
    
    #Lista dei processi aperti
    lista_process = []
    
    for col_analysis in total_columns:

        p1 = Process(target= extractIndexToDelete, args=(df_balanced_train,col_analysis, list_Index_To_Delete,))
        lista_process.append(p1)
        p1.start() 

    for process in lista_process:
        process.join()
    
    print()
    print("Indici")
    print(len(list_Index_To_Delete))
    #Prendere il set degli indici da eliminare visto che ci sono delle ripetizioni
    list_Index_To_Delete = list(set(list_Index_To_Delete))
    
    print("Old Shape")
    print(df_balanced_train.shape)
    
    
    df_balanced_train.drop(list_Index_To_Delete, inplace=True)
    df_balanced_train.reset_index(drop=True, inplace=True)
    
    print("New Shape")
    print(df_balanced_train.shape)
    
    #input()    
    
    print()
    
    #Comment this Part
#    print("CONTROL ABOUT SMOOTE")
    
#    for ll in list(set(df_balanced_train["Label DSCP"])):
#        check = df_balanced_train[df_balanced_train["Label DSCP"] == ll]
#        for col in check.columns:
#            print()
#            print("Work with: " + str(ll))
#            print(col)
#            print(Counter(check[col]))
#            print()
#            print()
#            
#            input()    
#    
#    print()

#    Cancellata tale parte per ora, i risultati non sono soddisfacenti    
#    print("Cancelliamo i duplicati")
#    df_balanced_train.drop_duplicates(inplace = True)
#    print(df_balanced_train.shape)

#    
    #input()
    
    

    ###############  Change Working Directory #####################
    
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()
    
    #Now we have to change this path and enter in our new folder
    os.chdir('./' + name_folder)
    print("This is the NEW  cwd:  " + os.getcwd())
    print()
    
    # =============================================================================
    #                       DIMENSIONALITY REDUCTION (PCA & LDA)                  
    # =============================================================================
    
    #Now we have to evaluate what we obtain using these 2 different techniques for
    #the Dimensionality reduction. We have to remember that PCA is Unsupervised while
    # LDA is supervised. The first one will maximize the variance into the all dataset
    #without considering the classes while LDA maximezes the variance between the 
    #classes.
    
    print("We can see the dimensionality of the balanced train")
    print()
    print("Number of observation")
    print(df_balanced_train.shape[0])
    print("Number of variables")
    print(df_balanced_train.shape[1])
    print()
    print()
    
    #Prova per ridurre la quantità di pacchetti
    #df_balanced_train = df_balanced_train.drop_duplicates()
    #print(df_balanced_train.shape[0])
    
    #Estrarre pacchetti "EF"
    print(df_balanced_train.columns)
    

    df_balanced_train.to_pickle("Dung.pkl")
    
    df  = dimensionality_reduction(dataframe = df_balanced_train)
    
    
    print()
    print("We have finished the LDA Part")
    print() 
    
    df.to_pickle("dataFrame_bilanciata.pkl")
    
    print()
    print("Save the DataFrame balanced")
    print() 
    
    print("Overview of the reduction on the dataset")
    print()
    print(df.head())
    print()
    print()
    
    
    #=============================================================================
    
    #READING THE DATAFRAME WHEN WORKING Locally:
    
    #import pickle
    
    #with open('dataFrame_bilanciata.pkl', 'rb') as f:
    #    df = pickle.load(f)
    
    # =============================================================================
    #                             CLUSTERING PART
    # =============================================================================
    
    
    print()
    print("CLUSTERING PART !!!")
    print()
    
    #Taking the train dataset from what we have obtained,
    # after the Dimensionality Reduction
    
    train = np.array(df.iloc[:,1:])
    
    
    ### K-MEANS
    
    print()
    print("Working with the K-Means")
    print()
    
    print("Now we evaluate the result with k = 5 centroids")
    
    y_kmeans, centroidi = Cluster(data = train, algo = "K-Means")
    err, colori = error_Cluster(y_kmeans, df)
    
    #Plot Cluster 
    
    '''
    plot_2D_cluster(data = train, result = y_kmeans, color_clutser = colori, method= "K-Means", centroids=centroidi)
    plot_3D_cluster(data = train, result = y_kmeans, color_clutser=colori, method = "K-Means", centroids= centroidi )
    '''
    print()
    print("The total error with K-Means is : ")
    print(err)
    
    input()
    
    # =============================================================================
    #                                   SILHOUTTE COMPARISON 
    # =============================================================================
    
    #This part is made for having an idea about the optimal number of cluster
    #this metrics is useful for evaluate convex cluster so using K-Means
    
    #Taking X and y for making the evaluation
    X = df.iloc[:,1:].values
    y = df["Label DSCP"].values
    
    print()
    print("Silhoutte Metrics: ")
    print()
    
    #Commentare da qui se già selezionato il numero di cluster
    
    result_Silh = {}
    #VM
    #for peso in [250000,500000,1000000,5000000]:
    #Local
    #for peso in [500, 1000, 5000]:
    #VM
    for peso in [5000]:
    #for peso in [300, 400, 500]:
        val = Silhouette_metrics_noPlot(start = 5, stop = 75, X = X, y=y, dataframe = df, data = train, sample_size = peso)
        result_Silh[peso] = val
    
    print()
    print("Results obtained with Silhouette method :")
    print(result_Silh)
    print()
    
    
    
    # =============================================================================
    #                   Plot Silhouette Results with the Sample Size
    # =============================================================================
    #This plot is useful to understandig how we can sample from our new clusters,
    #especially the size of the cluster how big it has to be. And see the variation of
    #Silhouette Index according to the variation of the size considered and the k
    # number of clusters.
    
    print()
    print("Plot to compare the sample size")
    print()
    
    stars = list(range(5,76,5))
    #stars = list(range(15,36))
    
    plt.figure(figsize=(10,6))
    
    for k in result_Silh:
        plt.plot(stars, result_Silh[k], marker='o', label=str(k))
    
    plt.xticks(stars)
    plt.title("Silhouette Evaluation")
    plt.xlabel("K-Centroids")
    plt.ylabel("Silhouette Index")
    plt.legend(loc='best', title = "Sample Size")  # legend text comes from the plot's label parameter.
    plt.savefig("Comparison_between_clusters_variation_size.png", dpi = 150)
    plt.show()
    plt.close()
    
    print()
    print("Saved the figure for comparing the sample size")
    print()
    
    # =============================================================================
    #                    Extract max value for the Silhouette Index
    # =============================================================================
    
    #In this case we are using 500 as sample size, to make the plot is needed only
    #to use one of the possible sample size.
    
    index_max = {i:0 for i in range(len(result_Silh[5000]))}
    for lista in result_Silh.values():
    
        max_value = max(lista)
        max_index = lista.index(max_value)
        #print(max_index,max_value)
        index_max[max_index] += 1
    
    pos = max(index_max.items(), key=operator.itemgetter(1))[0]
    
    optimal_k = list(range(5,76,5))[pos]
    #optimal_k = 25
    
    clusterer = KMeans(n_clusters = optimal_k, init = 'k-means++', random_state = 0)
    
    cluster_labels = clusterer.fit_predict(X)
    centroidi = clusterer.cluster_centers_
    
    print()
    print()
    
    err, colori = error_Cluster(cluster_labels, df)
    plot_3D_cluster(data = train, result = cluster_labels, color_clutser=colori, method = "K-Means", centroids= centroidi )
    
    
    #Commentare fino a qui se già selezionato il numero di cluster
    
    
    # =============================================================================
    # CLUSTER CON K = 5  to visualize the beginning distribution
    # =============================================================================
    # #clusterer = KMeans(n_clusters=5, init = 'k-means++', random_state=0)
    # #cluster_labels = clusterer.fit_predict(X)
    # #centroidi = clusterer.cluster_centers_
    # #print()
    # #
    # #err, colori = error_Cluster(cluster_labels, df)
    # #plot_3D_cluster(data = train, result = cluster_labels, color_clutser=colori, method = "K-Means", centroids= centroidi )
    # 
    # =============================================================================
    
    
    #WARNING: Choose the  ___SAMPLE WEIGHT___ according to the available values used for comparison 
    #graph
    
    #optimal_k = 25
    
    print()
    print("The optimal number of cluster is: " + str(optimal_k))
    print()
    
    input()
    
    
    for peso in [100000]:
        new_hierarchy, new_y = Silhouette_metrics(start = optimal_k, stop = optimal_k,
                                                  X = X, y=y, dataframe = df, data = train, sample_size = peso,
                                                  new_prior = "True")
        #new_hierarchy, new_y = Silhouette_metrics(start = optimal_k, stop = optimal_k, X = X, y=y, dataframe = df, data = train, sample_size = peso, new_prior = "True")
    
    # new_hierarchy = {"Class of service":[list of tuples (label cluster, Silhouette Index)]}
    
    print()
    print("This is the New Hierarchy about the priority: ")
    print()
    print(new_hierarchy)
    print()
    
    print("Save the new priority !!! ")
    print()
    
    #Saving Priority
    
    #FOR VM
    with open('../simulator/Priority0403.pkl', 'wb') as handle:
        pickle.dump(new_hierarchy, handle, protocol=pickle.HIGHEST_PROTOCOL)
    #FOR Local
    #with open('..//Priority.pkl', 'wb') as handle:
    #    pickle.dump(new_hierarchy, handle, protocol=pickle.HIGHEST_PROTOCOL)
        
    
    #In this part we are considering the New Labels to extract in which way are divided the packets 
    #according to the port used 
    
    print()
    print(df_balanced_train.head())
    print()
    print(len(df_balanced_train))
    print()
    print(new_y)
    print(len(new_y))
    print()
    
    print("We attach the new labels to the dataframe")
    df_balanced_train["new_label"] = new_y
    
    #We see the variables for the Port and print the new label, in this way we know the class of service
    #mainly assign to this Port.
    for i in df_balanced_train.columns:
        if "port" in i:
            print(i)
            df_nuovo = df_balanced_train[df_balanced_train[i] == 1]
            print(Counter(df_nuovo["new_label"]))
            print()
            
            #input()
        
    
    print()
    print("Now we create a new Dataframe according to our new Classifciation: ")
    print()
    
    #Creating the DataFrame for the next step : Classification & Simulation
    
    #Size of number of rows of our Dataframe after the classification with K-Means
    row = X.shape[0]
    print("This is the number of rows of X_Resampled: " + str(row))
    new_y = np.reshape(new_y,(row,1))
    
    #Concatenating the X and y into a numpy array
    new_data = np.concatenate((X, new_y), axis=1)
    
    #Columns for the DataFrame
    if X.shape[1] == 3:
        col = ["LDA_1","LDA_2","LDA_3","Label DSCP"]
    elif X.shape[1] == 2:
        col = ["LDA_1","LDA_2","Label DSCP"]
    
    #FINAL Dataframe with new labels
    new_Data_Frame = pd.DataFrame(data = new_data, columns = col)
    
    print()
    print("We have created our new dataframe and we save it !!!")
    print()
    
    new_Data_Frame.to_pickle("../NewDataFrame.pkl")
    
    
    #Otterremo un dizionario {peso:[indice di silhouette al variare di K]}
    #Fare un grafico come : https://stackoverflow.com/questions/23687247/efficient-k-means-evaluation-with-silhouette-score-in-sklearn
    
    print()
    print("Finish Silhoutte")
    print()
    '''
    
    # =============================================================================
    # SECOND METHOD for Clustering : DBSCAN
    # =============================================================================
    
    print()
    print("Working with the DBSCAN")
    print()
    
    #Il problema di dbscan è che la complessità è n^2 quindi dobbiamo droppare
    #le osservazioni che si ripetono e tenere l'informazione delle occorrenze
    
    #Here the centroids there aren't
    
    d_b = df.copy()
    
    d_b = d_b.groupby(d_b.columns.tolist()).size().reset_index().rename(columns={0:'records'})
    
    print()
    print(d_b.head())
    print()
    print("The number of rows previously were: " + str(df.shape[0]))
    print()
    print("The number of rows Now are: " + str(d_b.shape[0]))
    print()
    
    print()
    print(Counter(d_b["Label DSCP"]))
    print()
    
    train = np.array(d_b.iloc[:,1:-1])
    
    
    print()
    vicini = list(set(d_b["records"]))
    print(type(vicini))
    vicini = sorted(vicini, reverse = True)
    vicini = vicini[0:10]
    for i in vicini:
        print(i)
        print(set(d_b[d_b["records"] == i]["Label DSCP"]))
        print()
    print()
    print("DAJE")
    
    
    y_dbscan, centroidi = Cluster(data = train, algo = "DBSCAN", peso = d_b.iloc[:,-1].values)
    err, colori = error_Cluster(y_dbscan, d_b)
    
    #Plot Cluster
    
    plot_2D_cluster(data = train, result = y_dbscan, color_clutser=colori, method = "DBSCAN", centroids= centroidi )
    plot_3D_cluster(data = train, result = y_dbscan, color_clutser=colori, method = "DBSCAN", centroids= centroidi  )
    
    print("The total error with DBSCAN is : ")
    print(err)
    
    # #Predict GMM cluster membership
    #print("Gaussian")
    #kmeans = GaussianMixture(n_components=5 ,covariance_type= "full"  )
    #y_kmeans = kmeans.fit_predict(train)
    #
    #err, colori = error_Cluster(y_kmeans, df)
    
    
    # Una volta scelto il metodo, probabilmente KMeans, 
    # dobbiamo aggiungere la nuova label al dataframe.
    
    #Salvare il dataframe ed iniziarlo a lavorare su un nuovo file
    
    # A questo punto richiamare gli algoritmi di 
    # classificazione e valutare il migliore.
    
    #Ora la classificazione sarà multiclasse quindi dobbiamo cambiare il codice
    
    '''
if __name__ == '__main__':
    
    start_complete_time = time.time()
    
    main()        
    print()
    print("Final Complete Time of Execution")
    print("--- %s seconds ---" % (time.time() - start_complete_time))
