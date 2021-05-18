# -*- coding: utf-8 -*-
"""
Created on Fri Apr 12 10:41:38 2019

@author: Davide
"""

from Functions import *
import os 
from os import system as cmd
import sys
import random
import time
from multiprocessing import Process, Manager




if __name__ == '__main__':
    
    
    #Sys used to pass the name of the file
    print()
    print ("This is the name of the script: ", sys.argv[0])
    print()
    
    #VM
    list_files = glob.glob("./data2019/*.pcap")
    #Local
    #list_files = glob.glob("./data2019/*.pcap")
    
    print(list_files)
    #Select the position of the .pcap file that we use for the training part
    i = int(sys.argv[1])
    elem = list_files[i]
    
    print()
    print("I'm working on: " + elem)
    print()
    
    # Define the name of the directory to create:
    
    #VM
    name_folder = "Analysis_" + elem.split("/")[-1][:8]
    #Local
    #name_folder = "Analysis_" + elem.split("/")[-1].split("\\")[-1][11:25] 
    
    print()
    print("This is the name folder " + name_folder)
    print()
    
    try:  
        os.mkdir(name_folder)
    except OSError:  
        print ("Creation of the directory %s failed" % name_folder)
    else:  
        print ("Successfully created the directory %s " % name_folder)
    
    print()
    
    #In this part we split the trace through -editcap.
    #We cut the trace every n-pkt that we can specify.
    
    #For VM
    cmd('editcap -c 5000000 ' + elem +' ./' + name_folder + '/PiccoloFile.pcap')
    #For Local - (In the Local File we have to express the entire Path for editcap)
    #cmd('C:/"Program Files"/Wireshark/editcap -c 100000 ' + elem + ' ./' + name_folder + '/small_file.pcap')
    
    print()
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()
    
    #Now we have to change this Path and enter in our new folder.
    
    os.chdir('./' + name_folder)
    print()
    print("This is the NEW  cwd:  " + os.getcwd())
    print()
    
    #Creation of 3 folders where we store the information about the trace
    
    directory_1 = 'FeaturesDataFrame'
    directory_2 = 'OccurrencesDetailed'
    directory_3 = 'Images_Distribution'
    
    lista_dir_new = [directory_1, directory_2, directory_3]
    
    for directory in lista_dir_new:
        try:  
            os.mkdir(directory)
        except OSError:  
            print ("Creation of the directory %s failed" % directory)
        else:  
            print ("Successfully created the directory %s " % directory)
    
    print()

    
    #Bring all the slices of the .pcap trace  
    splitting_file = glob.glob('./*.pcap')
    #Ordering according to the number of cut
    splitting_file = sorted(splitting_file)
    print(len(splitting_file))
    
    #Select the number of pcap to consider. 
    # (Pkt in the first 5 minutes are about 40 Mln)
    
    #For VM
    #Taking randomly the pcap
    #xx = random.sample(range(len(splitting_file) - 10), 15)
    #Order case
    #xx = list(range(0,200))
    #For Local
    #xx = random.sample(range(len(splitting_file)), int(len(splitting_file)/2))
    xx = list(range(0,3))
    print()
    
    #All possible files we can select
    print("Possible number of files is :")
    print(len(splitting_file))
    print()
    print("This is the number of pcap values selected: ")
    print()
    print(len(xx))
    
    
    # -- ICMP Analysis --
    manager = Manager()
    
    list_ICMP = manager.list()
    
    start_time = time.time()
    
    lista_process = []
    
    for i in xx:
    
        #print(fl_name)
        file = splitting_file[i]
        p1 = Process(target= extract_Info_pckt, args=(file,list_ICMP,))
        lista_process.append(p1)
        p1.start()
    
    for process in lista_process:
        process.join()
    
    print()
    print("We finish to read all the trace")
    print("--- %s seconds ---" % (time.time() - start_time))
    input()
    
    #Saving the list of ICMP packet
    with open('list_ICMP_packet.pkl', 'wb') as f:
        pickle.dump(list_ICMP, f)
        
    dizionario, tot_pkt = packetAnalysis()
    
    print()
    print("Dictionary")
    print(dizionario)
    print()
    
    print()
    print("Packets")
    print(tot_pkt)
    print()
    
    
    Statistics(dizionario, tot_pkt)
    
    #Preparing the final dataset to be used in the Clustering Part
    #final_data = cleaning_Data()
    #
    ##There are some NULL values in the field: FRAGMENT and FLAG MF (fare un check !!!)
    #print(final_data)
    
    
    print()
    print("Finish reading pcap")
