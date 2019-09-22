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

print()
print ("This is the name of the script: ", sys.argv[0])
print()

#VM
list_files = glob.glob("./data2019/*.pcap")
#Local
#list_files = glob.glob("./data2019/littleProva/*.pcap")

#Select the position of the .pcap file that we use for the training part
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
#We cut the trace every n pkt that we specify.

#For VM
cmd('editcap -c 1000000 ' + elem +' ./' + name_folder + '/PiccoloFile.pcap')
#For Local - In the Local File we have to express the entire Path for editcap 
#cmd('C:/"Program Files"/Wireshark/editcap -c 500 ' + elem + ' ./' + name_folder + '/small_file.pcap')

print()
print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
print()

#Now we have to change this Path and enter in our new folder.

os.chdir('./' + name_folder)
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

#Select the number of pcap to consider. Pkt in the first 5 minutes are about 
# 30 Mln. So, the cut of 1 Mln will create 30 .pcap files.

#For VM
xx = random.sample(range(10), 5)
#For Local
#xx = random.sample(range(len(splitting_file)), int(len(splitting_file)/2))

print()
#Al possible files to be selected
print(len(splitting_file))
print()
print("This is the number of pcap values selected: ")
print()
print(xx)

#Extract all the .pcap file and starting to clean and retrieve the variables

for i in xx:
    print()
    print(i)
    file = splitting_file[i]
    print(file)
    
    extract_Info_pckt(file)
    print()
    print("Finished completely the analysis of our file .pcap")
    print()
    
dizionario, tot_pkt = packetAnalysis()

print()
print("Packets")
print(tot_pkt)
print()
    
Statistics(dizionario, tot_pkt)

#Commentato Ora
final_data = cleaning_Data()

#There are some NULL values in the field: FRAGMENT and FLAG MF
print(final_data)

#Oversampling
#ff = Oversampling(final_data)
#print(ff.columns)

'''

# PARTE UTILE PER RICAVARE CONFUSION MATRIX CON DATASET BILANCIATO

Oversampling_and_PCA(final_data)
Validation()
GridSearch()

# PARTE UTILE PER RICAVARE CONFUSION MATRIX CON DATASET SBILANCIATO

DataFrame_PCA = PCA_decomposition(final_data)
Classification(DataFrame_PCA)
'''
print()
print("Finish SANGEPPATO")