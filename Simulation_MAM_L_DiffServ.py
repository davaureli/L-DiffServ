# -*- coding: utf-8 -*-
"""
Created on Sun May 19 14:18:00 2019

@author: Davide
"""
#### Libraries

import heapq as hq
import numpy as np
#import pandas as pd
from copy import copy
import pickle
from collections import Counter
import collections
import matplotlib.pyplot as plt
import math

import hashlib

dscp_tab = {}

#Service class hierarchy

for i in range(64):
    #Best Effort
    if i == 0:
        dscp_tab[str(i)] = 1
    #Scavenger
    elif i > 0 and i < 8:
        dscp_tab[str(i)] = 0
    #AF1
    elif i >= 8 and i < 18:
        dscp_tab[str(i)] = 2
    #AF2
    elif i >= 18 and i < 26:
        dscp_tab[str(i)] = 3
    #AF3
    elif i >= 26 and i < 34:
        dscp_tab[str(i)] = 4
    #AF4
    elif i >= 34 and i < 40:
        dscp_tab[str(i)] = 5
    #EF
    elif i >= 40 and i < 48:
        dscp_tab[str(i)] = 6
    #Network or Internetwork control
    elif i>= 48:
        dscp_tab[str(i)] = 7

#Reading the file for extracting the tuples from the DataFrame

#Trace analyzed
with open('dataframe_Simulation0528.pkl', 'rb') as f:
    data_start = pickle.load(f)


print()
print("Total Number of Packets")
print(data_start.shape[0])

#print()
#print(set(data_start["Label DSCP"]))
#print(data_start.iloc[0])
#print()

#Reading the new Priority, where we have stored all the info about the possible subclasses

with open('Priority.pkl', 'rb') as f:
    priority = pickle.load(f)

#print()
#print(priority)
#print()

#Dictionary new_DSCP_tab = old class of Service
new_dscp_tab = { elem[0] : k for k,v in priority.items() for elem in v} 
   
#print()
#print(new_dscp_tab)
#print()

class_of_service_prior = ["Not Known", "best effort", "AF","Critical voice RTP","Network or Intenetwork control"]

#Order for the Simulation
update_dscp_tab = { }
order = 0
for poss in class_of_service_prior:
    for k in new_dscp_tab.keys():
        if poss == new_dscp_tab[k]:
            update_dscp_tab[k] = order
            order += 1

print()
print(update_dscp_tab)
print()


# STRUCTURE CREATION for the SIMULATION PART          

#Commented from here to the next advise if you have already the structure

# 2 different structures : classic DSCP & new DSCP (our proposal)

file_classic_DSCP = []
file_new_DSCP = []

possible_hash = []

for i in range(data_start.shape[0]):
    
    #Hash function for the 4 fields
    block = data_start.iloc[i]['IP_SRC'] + " " + data_start.iloc[i]['IP_DST'] + " " + str(data_start.iloc[i]['src_port']) + " " + str(data_start.iloc[i]['dst_port'])
    block = block.encode('utf8')
    block = hashlib.sha256(block)
    block = int(block.hexdigest(), 16)    
    
    possible_hash.append(block)
    #First model with DiffServ DSCP
    file_classic_DSCP.append((data_start.iloc[i]['time'], (0, dscp_tab[data_start.iloc[i]['Label DSCP']], data_start.iloc[i]['length'], block, data_start.iloc[i]['Label DSCP'])))
    
    #Second model with our DSCP
    file_new_DSCP.append((data_start.iloc[i]['time'], (0, update_dscp_tab[data_start.iloc[i]['New DSCP']], data_start.iloc[i]['length'], block, data_start.iloc[i]['New DSCP'])))
    
  
#See the structure of data !!! Print them    
#print(file_classic_DSCP[0])
#print(file_classic_DSCP[1])
#print()
#print()
#print(file_new_DSCP[0])
#print(file_new_DSCP[1])

#Save the 2 different structure, in this way we create the structure only once.

#Current DSCP Marking
with open('classicDSCP_0528.pkl', 'wb') as f:
    pickle.dump(file_classic_DSCP, f)
#New DSCP Marking
with open('newDSCP_0528.pkl', 'wb') as f:
    pickle.dump(file_new_DSCP, f)
    
#Saving even the all possible hash function obtained
with open('hash_possible_0528.pkl', 'wb') as f:
    pickle.dump(possible_hash, f)

print()
print("Saving the 2 different Structure")
print()



print()
print("Reading 2 different Structure")
print()

#Last part for ending the creation of the structure (stop here to comment)


#Once we created the 2 different data structure we can read them


#Current DSCP Marking
with open('classicDSCP_0528.pkl', 'rb') as f:
     file_classic_DSCP = pickle.load(f)
#New DSCP Marking
with open('newDSCP_0528.pkl', 'rb') as f:
     file_new_DSCP = pickle.load(f)

#Reading the possible Sessions encountered
with open('hash_possible_0528.pkl', 'rb') as f:
     possible_hash = pickle.load(f)

#Extract all the possible values of Hash we have obtained

print()
print("Number of sessions: ")
print(len(set(possible_hash)))
print()

'''
#Possible DSCP that we have, according to the current classification :
#print()
#print(Counter(data_start["Label DSCP"]))
#print()

#Number of packets analyzed
#print()
#print("Total number of packets analyzed: " + str(data_start.shape[0]))
#print()

print("Ok caricati i dati")

CREAZIONE DEL FLUSSO DI PACCHETTI SEGUENDO LA DISTRIBUZIONE DI ARRIVO DELLE CLASSI

#file = []
#n = 1000
#Generating the arrival of our packets following their exponential distribution
#lambda_types = [0.005, 0.1, 0.001, 0.005]
#
#for p_type in range(4):
#    times = pd.Series(np.random.exponential(lambda_types[p_type],n)).cumsum()
#    times = times[times<5]
#    sizes = 2**np.array(np.random.uniform(4,10,n),dtype=np.int)[:len(times)]
#    file += [(time,(0,p_type,size)) for time,size in zip(times,sizes)]
    
'''

##### Code for simulation #####

# Simulation changing the product 2T * C /sqrt(number of session)

total_discarded_pkt = []

#mark = "old"
#mark = "new"
poss_mark = ["old", "new"]

flussi_colpiti_current_DSCP = []
flussi_colpiti_proposal_DSCP = []

for mark in poss_mark :
    print("Working with this marking packets theory: ")
    
    print(mark)
    discarded_pkt_mrk = []
    
    print()
    print("Total Number of pkts that will be simulated: ")
    print(data_start.shape[0])
    print()
   
    for cap in [300000000, 400000000, 500000000, 600000000, 700000000, 800000000, 900000000, 1000000000]:
        print("Working with a capacity of " + str(cap) + " bit/sec")
        
        #Working with the percentage
        #tot = Capacity * 2TT / sqrt(# of sessions)
        tot = 2 * (cap * 0.250)/ math.sqrt(len(set(possible_hash)))
        
        # Possible Queue according to the current DSCP marking:
        #[Scavenger, Best Effort,  AF1,    AF2,     AF3,       AF4,     EF,    Network Control]
        
        #L-DiffServ environment
        queue_max_length_old = [0.15*tot, 0.4*tot, 0.06*tot, 0.06*tot, 0.06*tot, 0.06*tot, 0.16*tot, 0.05*tot]
        
        #Cisco Model
        #queue_max_length_old = [0.01*tot, 0.25*tot, 0.9*tot, 0.20*tot, 0.10*tot, 0.20*tot, 0.10*tot, 0.05*tot]
        
        router_speed_old = [ i/0.250 for i in queue_max_length_old]
    
        if mark == "old":
            queue_max_length = queue_max_length_old
            router_speed = router_speed_old
            
        elif mark == "new":
            
            #Creation of the queue for the new classification DSCP according to the value used for 
            #the current DSCP mark
            queue_max_length = []
            j = 0
            for elem in class_of_service_prior:
                for i in range(len(priority[elem])):
                    
                    if j>1 and j<6:
                        queue_max_length.append(sum(queue_max_length_old[2:6])/len(priority[elem]))
                    else:
                        queue_max_length.append(queue_max_length_old[j]/len(priority[elem]))
                if elem == "AF":
                    j += 4
                else:
                    j+= 1

                
            #Creation of the router speed differentiation for the new classification DSCP according 
            #to the value used for the current DSCP mark
            router_speed = []
            j = 0
            for elem in class_of_service_prior:
                #print(elem)
                for i in range(len(priority[elem])):
                    
                    if j>1 and j<6:
                        router_speed.append(sum(router_speed_old[2:6])/len(priority[elem]))
                    else:
                        router_speed.append(router_speed_old[j]/len(priority[elem]))
                if elem == "AF":
                    j += 4
                else:
                    j+= 1
            
            #print()
            #print(router_speed)
            #print()
    
        
        #Choose the data structure according to the marking
        if mark == "old":
            file = file_classic_DSCP
        elif mark == "new":
            file = file_new_DSCP        
        
        #Transform the data structure in a binary tree according to the time
        time_sequence = copy(file)
        hq.heapify(time_sequence)
        
        #Printing the time sequence we have not the real order of the structure
        #print(time_sequence)
        
        queues = []
        
        if mark == "old":
            number = 8
        elif mark == "new":
            #According to our number of service classes after the Silhouette
            number = len(new_dscp_tab) 
    
        for p_type in range(number):
            queues.append([])
            
        #Caracteristics for the last queue in the code
        #In this case there is no differentiation between old and new DSCP mark 
        
        priority_queue = []
        hq.heapify(priority_queue)
        
        size_last_queue = tot/2 #Dimension in Bit
            
        priority_router_speed = 10000000 #1 Kbit/sec in Uscita
        
        #Characteristics according to the marking:
        discarded = [0] * number
        
        discarded_last = [0] * number
        
        out = []
        
        discarded_type = []
        discarded_last_type = []
        
        last_queue_update = 0
        
        #Until we have element in the time sequence
        while time_sequence:
            
            #we extract the root
            app = hq.heappop(time_sequence)
            
            #Define the fields of the tuple
            (current_time,(event, d_type, size, block, real_DSCP)) = app
            
            #Possible Event values : 0 , 1, 2
            
            # 0 First Time Packet enter in the router
            if event == 0: #new packet
                
                #Check for queue dimension
                if sum(queues[d_type]) + size > queue_max_length[d_type]: #full queue
                    discarded[d_type] += 1
                    discarded_type.append(app)
                
                else: #queue not full according to the size
                    queues[d_type].append(size)
                    
                    if len(queues[d_type]) == 1: #empty queue
                        #print("First Packet in his queue type")
                        
                        #add new event to time_sequence = packet elaborated
                        time_to_complete = size/router_speed[d_type]
                        #updating time
                        time_completed = current_time + time_to_complete
                        
                        hq.heappush(time_sequence,(time_completed,(1,d_type,size,block,real_DSCP))) #size here is useless
            
            # 1 Second Time we see the Packet forwarding it into the final queue
            elif event == 1: #packet elaborated
            
                #insert in priority queue
                prior = 6 - d_type
                
                queues[d_type].pop(0) #drop elaborated packet
                
                #In case there were packets in the same queue as that class,
                #we need to serve the following packets to the processed one
                
                if len(queues[d_type])>0: #queue not empty
                       
                        #add new event to time_sequence = packet elaborated
                        new_size = queues[d_type][0]
                        
                        time_to_complete = new_size/router_speed[d_type]
            
                        time_completed = current_time + time_to_complete
            
                        hq.heappush(time_sequence,(time_completed,(1, d_type, new_size, block, real_DSCP))) 
                        
                #The idea is to add the packets regardless, updating the size of the queue.
                #Insert the element inside the second queue
                
                last_queue_update += size
                
                hq.heappush(priority_queue,( prior, current_time, size, block, real_DSCP))
                
                #Check for the size of the Priority queue
                while last_queue_update > size_last_queue: #full queue
                    
                    #We extract from the queue, having also added the extra packet,
                    #the packet that has the lowest priority. However before creating
                    #such queue we decided to insert a reverse priority for
                    #build the tree correctly.
                    drop_packet = hq.nlargest(1,priority_queue)[0]
                    #print(drop_packet)
    
                    #Removed the packet
                    priority_queue.remove(drop_packet)
                    
                    #The priority_queue is retransformed into a binary tree
                    hq.heapify(priority_queue)
                    
                    #Update the account of discarded packets in the second queue
                    discarded_last[d_type] += 1
                    #Updated discarded packet type
                    discarded_last_type.append(drop_packet)
                    #Update the last size of the queue to count the number of packets drop
                    last_queue_update -= drop_packet[2]
                    
                    
                #Check for the packets in the last queue
                if len(priority_queue) == 1:
                    #add new event to time_sequence = packet elaborated
                    time_to_complete = size/priority_router_speed
        
                    time_completed = current_time + time_to_complete
        
                    hq.heappush(time_sequence,(time_completed,(2,d_type,size,block,real_DSCP))) #size here is useless
                    
            # 2 Last Time we see the Packet do dequeue from priority_queue    
            elif event == 2:
                
                #print("Packet completely elaborated")
                out.append(d_type)
                
                hq.heappop(priority_queue) #drop elaborated packet 
                
                last_queue_update -= size #drop elaborated packet
                
                #Processing of the package following the one just finished processing
                if len(priority_queue)>0: #queue not empty
                    
                    #add new event to time_sequence = packet elaborated
                    new_size = priority_queue[0][2] #(priority, current_time, size,....)
                    
                    time_to_complete = new_size/priority_router_speed
        
                    time_completed = current_time + time_to_complete
        
                    hq.heappush(time_sequence,(time_completed,(2,d_type,new_size,block,real_DSCP))) #size here is useless
                
            else:
                #Check for errors
                print("ERROR")
    
        print()
        print("We are working with this marking idea: " + mark)
        print()
        print("Packets discarded in the first queue:")
        print(discarded)
        print()
        
        print()
        print("Packets discarded in the last queue:")
        print(discarded_last)
        print()
        
        print()
        print("Tot discarded")
        print(sum(discarded + discarded_last))
        print()
        
        #Count the number of sessions hit by packet loss (at least 1 packet)
        print("Now count the number of broken sessions")
        
        discarded_pkt_mrk.append(sum(discarded + discarded_last))
        
        #print(discarded_last_type)
        
        #Hit flows for the Plot
        diz_hash_discarded = { h:0 for h in list((set(possible_hash)))}
                
        #In discarded packets we have tuples of discarded packets
        for pkt in (discarded_type):
            #Extract the identification Hash for the session
            if pkt[1][3] in diz_hash_discarded:
                #Update the count of packet discarded according to the session
                diz_hash_discarded[pkt[1][3]] += 1
                
        #Dictionary for the flows not hit
        counter_hash_discarded = Counter(diz_hash_discarded.values())
        print()
        print("Number of flows hit")
        print(len((set(possible_hash))) - counter_hash_discarded[0])
        flows_affected = (len((set(possible_hash))) - counter_hash_discarded[0])/len((set(possible_hash)))
        
        if mark == "old":
            flussi_colpiti_current_DSCP.append(flows_affected)
        elif mark == "new":
            flussi_colpiti_proposal_DSCP.append(flows_affected)
            
        print()
    total_discarded_pkt.append(discarded_pkt_mrk)

#print()
#print(total_discarded_pkt)
#print()
#print(discarded_type)


with open('./MAM/MAM_DSCP_Current_0528.pkl', 'wb') as f:
    pickle.dump(flussi_colpiti_current_DSCP, f)
with open('./MAM/MAM_DSCP_Proposed_0528.pkl', 'wb') as f:
    pickle.dump(flussi_colpiti_proposal_DSCP, f)

print()
print("Saved")
  