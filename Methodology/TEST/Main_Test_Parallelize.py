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
import random
import time
from multiprocessing import Process, Manager



def main():
    
    print ("This is the name of the script: ", sys.argv[0])
    print()
    
    #VM
    #list_files = glob.glob("./data2019/*.pcap")
    #Local
    list_files = glob.glob("./data2019/*.pcap")
    
    print()
    print(list_files)
    
    i = int(sys.argv[1])
    elem = list_files[i]
    
    print()
    print("I'm working on: " + elem)
    print()
    
    # Define the name of the directory to be created:
    
    #VM
    name_folder = "Analysis_" + elem.split("/")[-1][:8]
    #Local
    #name_folder = "Analysis_" + elem.split("/")[-1].split("\\")[-1][11:25] 
    
    
    print("This is the name folder " + name_folder)
    print()
    try:  
        os.mkdir(name_folder)
    except OSError:  
        print ("Creation of the directory %s failed" % name_folder)
    else:  
        print ("Successfully created the directory %s " % name_folder)
    
    print()
    
    #For VM
    cmd('editcap -c 500000 ' + elem +' ./' + name_folder + '/PiccoloFile.pcap')
    #For Local -Percorso completo ad Editcap  
    #cmd('C:/"Program Files"/Wireshark/editcap -c 50000 ' + elem + ' ./' + name_folder + '/small_file.pcap')
    
    
    
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()
    
    #Now we have to change this path and enter in our new folder
    os.chdir('./' + name_folder)
    print("This is the NEW  cwd:  " + os.getcwd())
    print()
    
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
    splitting_file = glob.glob('./*.pcap')
    #Ordering according to the number of cut otherwise it could be disordered
    splitting_file = sorted(splitting_file)
    print()
    
    #For VM
    #Our idea is to test the last part of the trace
    #xx = random.sample(range(len(splitting_file)), 5)
    #xx = [0,1,2,3,4,5,6,7,8, len(splitting_file) -8, len(splitting_file) -7,len(splitting_file) -6,
    #      len(splitting_file) -5, len(splitting_file) -4, len(splitting_file) -3, len(splitting_file) -2]
    #xx = [len(splitting_file) -4]
    xx = [ i for i in range(200,210)]
    #For Local
    #xx = random.sample(range(len(splitting_file)), 5)
    
    print(len(splitting_file))
    
    print("These are the pcap values selected: ")
    print()
    print(xx)

    
    
    #ICMP Analysis
    manager = Manager()
    
    list_ICMP = manager.list()
    
    start_time = time.time()
    
    lista_process = []
    
    for i in xx:
        #print(fl_name)
        file = splitting_file[i]
        p1 = Process(target= extract_Info_pckt, args=(file, list_ICMP,))
        lista_process.append(p1)
        p1.start()
    
    for process in lista_process:
        process.join()
    
    print()
    print("We finish to read all the trace")
    print("--- %s seconds ---" % (time.time() - start_time))
    
    #Saving the list of ICMP packet
    with open('list_ICMP_packet.pkl', 'wb') as f:
        pickle.dump(list_ICMP, f)
        
    dizionario, tot_pkt = packetAnalysis()
    
    print()
    print("Dizionario")
    print(dizionario)
    print()
    
    print()
    print("Packets")
    print(tot_pkt)
    print()
    
    #For now we do not consider this part 
    #Statistics(dizionario, tot_pkt)
    
    
if __name__ == '__main__':
    main()