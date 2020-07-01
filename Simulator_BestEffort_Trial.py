# -*- coding: utf-8 -*-
"""
Created on Sun Jun 14 10:24:27 2020

@author: user
"""



from Functions_Simulator_LDIFFSERV import *
from collections import Counter
import pickle

totale_pacchetti_scartati = []
totale_sessioni_colpite = []

print("Inizio Nuova Simulazione")


for i in range(1):
    
    print("Volta___" + str(i))

    start = timeit.default_timer()
    
    
    #Reading File
    #path_file = "C:\\Users\\user\\Desktop\\Trace_0403_DSCP_label.txt"
    
    path_file = "./Trace_0508_DSCP_label.txt"
    
    
    #Transfer data into a list, reading line by line
    data = []
    
    file = open(path_file, "r")
    for i in file:
        data.append(i.split())
        
    #Create DataFrame
    dataFrame = pd.DataFrame(np.array(data[1:]), columns = data[0])  
    
#    print(dataFrame.columns)
#    print()

#    lista_hash= []

#    for i in dataFrame.index:
#        lista_hash.append(dataFrame.loc[i]['IP_SRC'] +
#                          dataFrame.loc[i]['IP_DST'] + 
#                          dataFrame.loc[i]['Protocol'] +
#                          dataFrame.loc[i]['src_port']+
#                          dataFrame.loc[i]['dst_port'])
#    print("Session")
#    print(len(set(lista_hash)))
#    #input()
    
    #Select a Specific DSCP 
    
    #Creazione dizionario vuoto
    dict_DSCP_class = {}
    
    dict_DSCP_label = {"BE":["0"], "Scavenger":[str(i) for i in range(1,8)],
                       "AF": [ str(i) for i in range(8,40)],
                       "EF":[ str(i) for i in range(40,48)],
                       "NIC":[ str(i) for i in range(48,64)]}
    
    dict_DSCP_numberClass = {"BE":0, "Scavenger":1, "AF":2, "EF":3, "NIC":4}
       
    
    diz_max_length = {}    
    
    for k in dict_DSCP_numberClass:
        
        #print(k)
               
        
        data_analysis = dataFrame[dataFrame["LabelDSCP"].isin(dict_DSCP_label[k])].copy()
        
        #Transform length column into integer type
        data_analysis["length"] = data_analysis["length"].astype(int)
        diz_max_length[k] = max(data_analysis["length"])*8
        
        dict_DSCP_class = dictionaryCreation(data_analysis = data_analysis,
                                             modello_type = "LR",
                                             labelDSCP = k, 
                                             codiceDSCP = dict_DSCP_numberClass[k],
                                             dizionarioParametri = dict_DSCP_class)
    											 
    
    #print(dict_DSCP_class)
    
    #rate = 240
    
    buffer_size = 0
    for dscp in dict_DSCP_class:
        buffer_size += dict_DSCP_class[dscp]["buff_len"]
        
#    print()
#    print("Total Buffer Size is: " + str(buffer_size) + "bit")
#    print()
    
    bandwidth = 0
    for dscp in dict_DSCP_class:
        bandwidth += dict_DSCP_class[dscp]["reserved_bandwidth"]
    rate = bandwidth
    
#    print()
#    print("Total Bandwidth: " + str(bandwidth) + "bit")
#    print()
    
    #input()
    
    #Aggiunta - Teorema di Parekh-Gallager
    for kiave in dict_DSCP_class:
        #print(dict_DSCP_class[kiave]['buff_len'])
        
        val_to_add = int((dict_DSCP_class[kiave]['reserved_bandwidth']/bandwidth)*diz_max_length[kiave])
        #print(val_to_add)
        
        #Uncommented to add the Theorem
        #dict_DSCP_class[kiave]['buff_len'] += int((dict_DSCP_class[kiave]['reserved_bandwidth']/bandwidth)*diz_max_length[kiave])
    
    #print(dict_DSCP_class)
    
    #Aggiunta la Quantità di Buffer Infinito
    for k in dict_DSCP_class:
        if k != "BE":
            dict_DSCP_class[k]["buff_len"] = 1000000000
    
    #input()
    
    #Caso di Banda assegnata pari a 0 inseriamo il valore del buffer
    for k in dict_DSCP_class:
        if dict_DSCP_class[k]["reserved_bandwidth"] == 0:
            dict_DSCP_class[k]["reserved_bandwidth"] = dict_DSCP_class[k]["buff_len"]
            
            
    politica = "MAM"
    aqm = False
    
    ##DiffServ
#    output_file = "./UB/sim_output_delay_0410.txt"
#    drop_file = "./UB/sim_output_drop_0410.txt"
#    trace_file = "Trace_0410_DSCP_label.txt"  
    
#    #L-DiffServ
    output_file = "sim_output_newDSCP_0508_delay.txt"
    drop_file = "sim_output_newDSCP_0508_drop.txt"
    trace_file = "Trace_0508_DSCP_label.txt"    
    	
    linecard = Linecard(rate, buffer_size, politica, aqm)
    
    for k in dict_DSCP_class:
        dict_DSCP_class[k]["coda"] =  Coda(dict_DSCP_class[k]["codice"])
        
    for k in dict_DSCP_class:
        linecard.add_buffer(dict_DSCP_class[k]["coda"], dict_DSCP_class[k]["codice"])
        
        linecard.riserva_banda(dict_DSCP_class[k]["codice"], 
                               dict_DSCP_class[k]["reserved_bandwidth"])
        
        linecard.riserva_buffer(dict_DSCP_class[k]["codice"], 
                                dict_DSCP_class[k]["buff_len"])
        
        
        
    scheduler_wfq = WFQ(linecard) # IMPORTANTE: DEFINIRE DOPO AVER TERMINATO LA LINECARD
    linecard.set_scheduler(scheduler_wfq)
    
    engine_simulatore = Engine()
    
    
    trace_reader = Lettore(trace_file)
    trace_reader.leggi_traccia(engine_simulatore, linecard)
    
    #print(engine_simulatore.eventi)
    
    conto = 0
        
    while engine_simulatore.sim_status():
        
        #print(engine_simulatore.eventi)
        start = timeit.default_timer()
    
        
        nextEvents = engine_simulatore.prossimo_evento()
    
        
        #stop = timeit.default_timer()
        #print('Time: ', stop - start)
        
    
        #start = timeit.default_timer()
        
        for event in nextEvents:
            
            
            if event.what == 'LC_idle':
                event.do_LC_free()
            if event.what == 'RX':
                event.do_RX()
        engine_simulatore.del_eventi_passati()
        
        #stop = timeit.default_timer()
        #print('Time: ', stop - start)
        
        conto +=1
        
        #print()
        #print(engine_simulatore.chiaveTempi)
        #print(engine_simulatore.eventi)
        #print()
        #print(conto)
        #if conto%100000 == 0:
            #input()
            
    with open(output_file, "w+") as a:
        for line in linecard.output_file:
            a.write(line)
    #
    #
    #
    with open(drop_file, "w+") as a:
        for line in linecard.drop_file:
            a.write(line)
                    
    stop = timeit.default_timer()
    print('Time: ', stop - start)
    
    print()
    print()
    
    
    
    #Statistiche L-DiffServ
    
    coppia = [] 
   
    f = open("sim_output_newDSCP_0508_drop.txt", "r")
    tot_discarded_newDSCP = []
    hash_deleted_newDSCP = []
    for i in f:
        tot_discarded_newDSCP.append(i.split("\t")[0])
        hash_deleted_newDSCP.append(i.split("\t")[1])
        
        coppia.append((i.split("\t")[1],i.split("\t")[0]))
    
    print()   
    print("Tot pacchetti Scartati") 
    print(len(tot_discarded_newDSCP)) 
    print("Scartati DSCP Nuovo")
    print(Counter(tot_discarded_newDSCP))
    print("Sessioni Colpite")
    print(len(set(hash_deleted_newDSCP)))
    
    #Plot Rivista - Dizionario Pacchetti colpiti in base al nuovo DSCP
    diz_final_percentage_packet = {}
    for elem in Counter(tot_discarded_newDSCP):
        diz_final_percentage_packet[elem] = round(Counter(tot_discarded_newDSCP)[elem]/len(tot_discarded_newDSCP),4)
    print()
    print("Results packets")
    print(diz_final_percentage_packet)
    print()
    
    
    #Plot analizzando singole sessioni in base al DSCP
       
    f = open("sim_output_newDSCP_0508_drop.txt", "r")

    hash_analysis = {}
    for i in f:
        if i.split("\t")[0] not in hash_analysis:
            hash_analysis[i.split("\t")[0]] = [i.split("\t")[1]]
        else:
            hash_analysis[i.split("\t")[0]].append(i.split("\t")[1])
        
    hash_analysis_final = { k:round(len(set(hash_analysis[k]))/len(set(hash_deleted_newDSCP)),4) for k in hash_analysis}
    print()
    print("Results Hash and DSCP")
    print(hash_analysis_final)
    
    
    
      
    #Add values in the global simulation results
    totale_pacchetti_scartati.append(len(tot_discarded_newDSCP))
    totale_sessioni_colpite.append(len(set(hash_deleted_newDSCP)))
    

print("Finish Simulation")

#with open('./UB/Packet_Discarded_0417_UB90.pkl', 'wb') as f:
#    pickle.dump(totale_pacchetti_scartati, f)
#
#with open('./UB/Session_Discarded_0417_UB90.pkl', 'wb') as f:
#    pickle.dump(totale_sessioni_colpite, f)


### Sessions Number 
    
#0403    5895
#0410    5511
#0417    7129
#0424    6287
#0501    11831
#0508    7274