# -*- coding: utf-8 -*-
"""
Created on Sat May 23 13:18:55 2020

@author: user
"""

### Simulatore

#Library
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import heapq
import time
import timeit

import math

sim_time = 0
flag_dscp = "Old"
class Packet:
    
    def __init__(self, real_dscp, hash_val, nw_src, nw_dst, nw_proto, tp_src, tp_dst, length, dscp, time):
        
        self.hash_val = hash_val
        self.nw_src = nw_src
        self.nw_dst = nw_dst
        self.nw_proto = nw_proto
        self.tp_src = tp_src
        self.tp_dst = tp_dst
        self.length = length
        self.dscp = dscp
        self.time = time
        
        #Aggiunto Ora
        self.real_dscp = real_dscp
        
        

class Lettore:
    
    def __init__(self, nome_file):
        self.nome_file = nome_file
        
    def leggi_traccia(self, engine, linecard):
        counter = 0
        
        with open(self.nome_file, "r") as a:
            traccia = a.readlines()
            for riga in traccia:
                
                if counter != 0:
                
                    pkt = self.genera_pacchetto(riga)
                    evento = Evento(linecard, pkt.time, "RX", engine)
                    evento.add_pacchetto(pkt)#Dove viene aggiunto il pckt
                    engine.add_evento(evento)
                    
                    
                counter +=1



    def genera_pacchetto(self, valore_campi):
        
        global flag_dscp
        campi = valore_campi.split()
        time = float(campi[0][6:]) #ripensare a come inserire il tempo
        nw_src = campi[1]
        nw_dst = campi[2]
        nw_proto = campi[3]
        tp_src = campi[5]
        tp_dst = campi[6]
        
        if flag_dscp == "Old":
            
            dscp = int(campi[8])
            
        elif flag_dscp == "New":
            
            dscp = int(campi[9])
            
        length = int(campi[4]) * 8
        
        #Aggiunta Hash - 25/05
        
        hash_val = hash(nw_src + nw_dst + tp_src + tp_dst + nw_proto)
        
        #Il campo 9 indica la nostra nuova classificazione
        real_dscp = int(campi[9])
        
        pkt = Packet(real_dscp, hash_val, nw_src, nw_dst, nw_proto, tp_src, tp_dst, length, dscp, time)
        
        return pkt
    
    
    
class Linecard:
    
    def __init__(self, rate, buffer_size, politica, aqm):
        self.rate = rate
        self.buffer_size = buffer_size
        self.politica = politica #MAM - RDM
        self.active_queue_management = aqm # si - no
        self.code = {}
        self.sagomatori = {}
        self.reserved_buffer = {}
        self.reserved_bandwidth = {}
        self.scheduler = None
        self.status = 'idle'
        self.output_file = []
        self.drop_file = []
        #Rio versione Marco (Buffer Util Threshold & Probability to discard)
        self.rio_param = {0:(1, 1), 1:(1, 1), 2:(1, 1), 3:(1, 1), 4:(1, 1)}
        
        #Rio per Best Effort (utile inserirlo nella creazione della linecard questi parametri)
        #self.rio_be_param = {28:(0.5,1), 6:(0.7, 0.6), 8:(0.5, 1), 0:(0.5, 1), 2:(0.5, 1), 4:(0.5, 1), 15:(0.5, 1), 7:(0.5, 1), 18:(0.5, 1)}
        
        
        #Traccia0417
#        self.rio_be_param = {7:(0.99,1),14:(1,1),20:(1,1),67:(1,1), 59:(1,1),12:(1,1), 4:(1,1), 16:(1,1),
#                             3:(1,1), 23:(1,1), 8:(1,1), 35:(1,1)}
        
#        self.rio_be_param = {7:(1,1),14:(1,1),20:(1,1),67:(1,1), 59:(1,1),12:(1,1), 4:(1,1), 16:(1,1),
#                             3:(1,1), 23:(1,1), 8:(1,1), 35:(1,1)}
        
        #Traccia0508
        self.rio_be_param = {18:(1,1), 2:(0.99,1), 8:(1,1), 9:(1,1), 0:(1,1), 23:(1,1), 5:(1,1),
                             12:(1,1), 24:(1,1), 6:(1,1), 28:(1,1), 72:(1,1)}
        

#        self.rio_be_param = {18:(1,1), 2:(1,1), 8:(1,1), 9:(1,1), 0:(1,1), 23:(1,1), 5:(1,1),
#                             12:(1,1), 24:(1,1), 6:(1,1), 28:(1,1), 72:(1,1)}        

        #Traccia 0501
#        self.rio_be_param = {7:(1,1),  0:(1,1), 25:(0.99,1), 3:(1,1), 14:(1,1), 5:(1,1), 24:(1,1),
#                             6:(1,1),50:(1,1), 11:(1,1), 8:(1,1), 45:(1,1)}
#        
#        self.rio_be_param = {7:(1,1),  0:(1,1), 25:(1,1), 3:(1,1), 14:(1,1), 5:(1,1),
#                             24:(1,1), 6:(1,1),50:(1,1), 11:(1,1), 8:(1,1), 45:(1,1)}
        
        #Traccia 0424
#        self.rio_be_param = {0:(0.99,1), 6:(1, 0.7), 40:(1,1), 47:(1,1), 4:(1, 1),
#                             2:(1,1),5:(1,1),22:(1,1), 21:(1,1)}
        
#        self.rio_be_param = {0:(1,1), 6:(1, 0.7), 40:(1,1), 47:(1,1), 4:(1, 1),
#                             2:(1,1),5:(1,1),22:(1,1), 21:(1,1)}
        
        #Traccia 0410 
#        self.rio_be_param = {1:(0.99,1), 2:(1, 0.7), 3:(1,0.7), 4:(1,1), 0:(1, 1)}
#        
#        self.rio_be_param = {1:(1,1), 2:(1, 1), 3:(1,1), 4:(1,1), 0:(1, 1)}
        
        #Traccia 0403 
#        self.rio_be_param = {28:(1,1), 6:(1, 1), 8:(1,1), 0:(1,1), 2:(0.9, 1),
#                             4:(1,1), 15:(1, 1), 7:(1, 1), 18:(1,1)}
        
#        self.rio_be_param = {28:(1,1), 6:(1, 1), 8:(1,1), 0:(1,1), 2:(1, 1),
#                             4:(1,1), 15:(1, 1), 7:(1, 1), 18:(1,1)}
        
    def add_buffer(self, coda, dscp):
        self.code[dscp] = coda
        
    def add_sagomatore(self, token_bucket, dscp):
        self.sagomatori[dscp] = token_bucket
    
    def get_queue_len(self, dscp):
        return self.code[dscp].get_queue_length()
    
    def set_scheduler(self, scheduler):
        
        self.scheduler = scheduler
        
    def riserva_banda(self, dscp, banda):
        self.reserved_bandwidth[dscp] = banda
    
    def get_banda_riservata(self, dscp):
        return self.reserved_bandwidth[dscp]
    
    def riserva_buffer(self, dscp, memoria):
        self.reserved_buffer[dscp] = memoria
    
    def coda_non_vuota(self):
        for dscp in self.code.keys():
            if self.code[dscp].get_queue_status() == True:
                return True
        return False
    
    
    def accoda_pacchetto(self, pkt):
        if pkt.dscp in self.sagomatori.keys():
            tb = self.sagomatori[pkt.dscp]
            if tb.policer(pkt) == False:
                pkt.dscp = 0
                print('PACCHETTO NON CONFORME\n')
                
        if self.politica == "MAM":
            
            #Se abbiamo un pacchetto Best Effort apriamo il discorso delle priorità
            if pkt.dscp == 0:
                #print(pkt.real_dscp)
                check = self.rio_BE(pkt)
            else:
                check = self.maximum_allocation_model(pkt)
#            print("Check")
#            print(check)
#            print("Length")
#            print(pkt.length)
#            print("Lunghezza coda")
#            print(self.reserved_buffer[pkt.dscp])
#            print("Occupazione")
#            print(self.code[pkt.dscp].get_queue_length())
            #print("DSCP")
            #print(pkt.dscp)
            #print()
        if self.politica == "RDM":
            check = self.russian_doll_model(pkt)
            
        if self.politica == "RIO":
            check = self.rio(pkt)
            
            
        if check == True:
            self.scheduler.last_received_pkt = pkt # aggiunto
            self.scheduler.updateVirtualClock(self) # aggiunto
            
            self.code[pkt.dscp].add_pacchetto(pkt)
            self.scheduler.receive(pkt, self)
        else:
            
#            print("Length")
#            print(pkt.length)
#            print("Lunghezza coda")
#            print(self.reserved_buffer[pkt.dscp])
#            print("Occupazione")
#            print(self.code[pkt.dscp].get_queue_length())            
#            print("Scartato")
#            print(pkt.real_dscp)
#            print()
            #input()
            self.drop_file.append(str(pkt.real_dscp) + "\t" + str(pkt.hash_val) +"\n")
        return check
    
    def trasmetti_pacchetto(self, engine):
               
        global sim_time
        pkt = self.scheduler.send(self)
        
        #if pkt.dscp == 12:
        #print("Scheduler pkt selected")
        #print(self.get_queue_len(pkt.dscp))
        #    print(pkt.length)
        #    print()
        
        self.code[pkt.dscp].del_pacchetto(pkt)
        self.status = 'busy'
        
        #if pkt.dscp == 12:
        #    print("Packet removed from queue")
        #    print(self.get_queue_len(pkt.dscp))
        #    print(pkt.length)
        #    print()
        
        #print(pkt.length)
        #print(self.rate)
        #input()
        
        Ttx = float(pkt.length) / float(self.rate)
        quando = max(pkt.time, sim_time) + Ttx
        evento = Evento(self, quando, "LC_idle", engine)
        engine.add_evento(evento)
        #self.output_file.append(str(pkt.time) + "\t" + str(quando) + "\t" + str(pkt.dscp) + "\t" + str(pkt.length) + "\n")
        self.output_file.append(str(pkt.time) + "\t" + str(quando) + "\t" + str(pkt.real_dscp) + "\t" + str(pkt.length) + "\n")
        
        
    def maximum_allocation_model(self, pkt):
        #print(pkt.real_dscp)
        if pkt.length <= (self.reserved_buffer[pkt.dscp] - self.get_queue_len(pkt.dscp)):
            return True
        else:
            
#            if pkt.dscp == 12:
#                
#                print("Scartiamo")
#                
#                print(self.reserved_buffer[pkt.dscp])
#                
#                print(self.get_queue_len(pkt.dscp))
#                
#                print(pkt.length)
#                
#                print()
                        
            return False
        
    def russian_doll_model(self, pkt):
        
        for dscp1 in self.code.keys():
            if dscp1 >= pkt.dscp:
                livello_consentito = 0
                buffer_consumato = 0
            
                for dscp2 in self.code.keys():
                    
                    if dscp2 <= dscp1:
                        livello_consentito += self.reserved_buffer[dscp2]
                        buffer_consumato += self.get_queue_len(dscp2)
                if pkt.length > (livello_consentito - buffer_consumato):
                    return False
        return True
    
    
    def rio(self, pkt):
        
        buffer_occupato = 0
        for coda in self.code:
            #print(coda)
            #print(self.code[coda])
            buffer_occupato += self.code[coda].get_queue_length()
            
        buffer_util = (buffer_occupato + pkt.length) / self.buffer_size
        
        #print("Utilizzato Buffer")
        #print(buffer_util)
        
        
        if buffer_util <= 1:
            if self.rio_param[pkt.dscp][0] >= buffer_util:
                return True
            else:
                if pkt.dscp > 2:
                    return True
                
                else:
                    #m = (self.rio_param[pkt.dscp][1] - 1) / (1 - self.rio_param[pkt.dscp][0])
                    m = (self.rio_param[pkt.dscp][1] - 1) / (1 - self.rio_param[pkt.dscp][0])
                    q = (- (self.rio_param[pkt.dscp][0])*m) + 1
                    
                    prob_acc = buffer_util * m + q
                    
                    if np.random.choice([True, False], p=[prob_acc, 1 - prob_acc]):
                        return True
                    
        return False
    
    #WRED
    def rio_BE(self, pkt):
            
#            buffer_occupato = 0
#            for coda in self.code:
#                #print(coda)
#                #print(self.code[coda])
#                buffer_occupato += self.code[coda].get_queue_length()
            
            #Buffer Occupation
            buffer_util = (self.code[0].get_queue_length() + pkt.length) / self.reserved_buffer[pkt.dscp]
            
            #print("Utilizzato Buffer Best Effort")
            #print(buffer_util)
            #print()
            #print()

            
            if buffer_util <= 1:
                #Posizione 0 abbiamo threshold (il min nel nostro caso)
                if self.rio_be_param[pkt.real_dscp][0] >= buffer_util:
                #if self.rio_be_param[pkt.real_dscp][0] >= buffer_util:
                    return True
                #Threshold superata del Min
                else:

                                       
                    #Parametri Buffer
                    max_B = 1
                    min_B = self.rio_be_param[pkt.real_dscp][0]
                    #Parametro Probabilità
                    p_max = self.rio_be_param[pkt.real_dscp][1]
                    
                    #Calcolo parametri AQM
                    m = p_max /(max_B - min_B)
                    q = p_max - m*(max_B)

                    #Probabilità di scartare
                    prob_discard = buffer_util * m + q
                    
                    #print("Calcolata la Prob di scartare")
                    #print(prob_discard)
                    #if prob_discard > 0.5:
                        #input()
                    if np.random.choice([True, False], p=[1 - prob_discard, prob_discard]):
                        return True
                        
            return False
        
    
class Coda:
    
    def __init__(self, dscp):
        self.dscp = dscp
        self.coda = []
        self.queue_length = 0
        #Aggiunta MaxLength Coda
        self.max_queue_occupation = 0
        
    def get_oldest_pkt(self):
        return self.coda[0]
    
    def add_pacchetto(self, pkt):
        self.coda.append(pkt)
        self.queue_length += pkt.length
        if self.queue_length > self.max_queue_occupation:
            self.max_queue_occupation = self.queue_length
        
    def del_pacchetto(self, pkt):
        self.coda.remove(pkt)
        self.queue_length -= pkt.length
        
    def get_queue_length(self):
        return self.queue_length
    
    def get_queue_status(self):
        if len(self.coda) > 0:
            
            return True
        else:
            
            return False
        
        
        
class TokenBucket:
    
    def __init__(self, b, r):
        self.bucket_size = b
        self.average_rate = r
        self.cumulative_traffic = 0
        
    def update_cumulative_traffic(self, pkt_length):
        self.cumulative_traffic += pkt_length
    
    def policer(self, pkt):
        self.update_cumulative_traffic(pkt.length)
        if self.cumulative_traffic <= (b + r * pkt.time):
            return True
        else:
            return False
        
        
        
class WFQ:
    
    def __init__(self, linecard):
        self.virtFinish = {}
        self.round = 0
        self.t_pred = 0
        self.last_received_pkt = None
        
        
        for dscp in linecard.code.keys():
            self.virtFinish[dscp] = [0]
            
    
    def receive(self, pkt, linecard):
        self.updateTime(pkt, linecard)
        
    def updateVirtualClock(self, linecard):
        global sim_time
        denominatore = 0
        for coda in linecard.code:
            if linecard.code[coda].get_queue_status():
                denominatore += linecard.reserved_bandwidth[linecard.code[coda].dscp]
                
        if denominatore == 0:
            denominatore = linecard.reserved_bandwidth[self.last_received_pkt.dscp]
            
        self.round = self.round + linecard.rate * (sim_time - self.t_pred) / denominatore
        self.t_pred = sim_time
        
    def updateTime(self, pkt, linecard):
        
        virtStart = max(self.round, self.virtFinish[pkt.dscp][-1])
        self.virtFinish[pkt.dscp].append(float(pkt.length) / float(linecard.get_banda_riservata(pkt.dscp)) + virtStart)
        #print("Lunghezza Pacchetto")
        #print(pkt.length)
        #print("DSCP")
        #print(pkt.dscp)
        #print("Banda Riservata")
        #print(linecard.get_banda_riservata(pkt.dscp))
        #input()
        
    def selectQueue(self, linecard):
        minVirtFinish = 10000000000000000000000000000000#math.inf
        for dscp in linecard.code.keys():
            if linecard.get_queue_len(dscp) > 0  and self.virtFinish[dscp][0] < minVirtFinish:
                minVirtFinish = self.virtFinish[dscp][0]
                queueNum = dscp
                
        del(self.virtFinish[queueNum][0])
        return queueNum
    
    def send(self, linecard):
        dscp = self.selectQueue(linecard)
        pkt = linecard.code[dscp].get_oldest_pkt()
        return pkt
    
    
    
class Evento:
    
    def __init__(self, linecard, when, what, engine):
        
        self.pkt = None
        self.linecard = linecard
        self.when = when
        self.what = what # 1) RX - 2) LC_idle
        self.engine = engine 
        
    def add_pacchetto(self, pkt):
        self.pkt = pkt
        
    def do_RX(self):
        
        #print("DSCP length")
        #print(self.pkt.length)
#        if self.pkt.dscp == 12:
#            print("DO RX")
#            print(self.linecard.status)
#            
#                
#            print(self.linecard.reserved_buffer[self.pkt.dscp])
#            
#            print(self.linecard.get_queue_len(self.pkt.dscp))
#            
#            print(self.pkt.length)
#            
#            print()
            
        #self.linecard.accoda_pacchetto(self.pkt)
        
        #Info Coda Check sui pacchetti scartati per verificare ipotesi Marco
#        if self.pkt.dscp == 4:
#            ist_tempo = self.when
#            stat = self.linecard.code[self.pkt.dscp].get_queue_status()
#            buff_residuo = self.linecard.reserved_buffer[self.pkt.dscp] - self.linecard.code[self.pkt.dscp].get_queue_length()
#            
#            print("Lung Pckt")
#            print(self.pkt.length)
#            print("Tempo")
#            print(ist_tempo)
#            print("Status")
#            print(stat)
#            print("Buff Residuo")
#            print(buff_residuo)
#            print()
#            input()
        
        self.linecard.accoda_pacchetto(self.pkt)
        
        if self.linecard.status == "idle":
            self.linecard.trasmetti_pacchetto(self.engine)
            
    def do_LC_free(self):
        
        
        self.linecard.status = "idle"
        self.linecard.scheduler.updateVirtualClock(self.linecard) #aggiunto
        if self.linecard.coda_non_vuota() == True:
            self.linecard.trasmetti_pacchetto(self.engine)
            
            
            
class Engine:
    
    def __init__(self):
        self.eventi = {}
        self.chiaveTempi = []
        
    def add_evento(self, evento):
        if evento.when in self.eventi.keys():
            self.eventi[evento.when].append(evento)
        else:
            self.eventi[evento.when] = [evento]
            heapq.heappush(self.chiaveTempi,evento.when)
            
    def del_eventi_passati(self):
        global sim_time
        self.eventi.pop(sim_time)
        #heapq.heappop(self.chiaveTempi)
        
    def prossimo_evento(self):
        global sim_time
        #start = timeit.default_timer()
        
        #sim_time = heapq.heappop(list(self.eventi.keys())) # Estrazione del minimo dal dizionario
        #print(len(self.eventi))
        #print(len(self.chiaveTempi))
        sim_time = heapq.heappop(self.chiaveTempi)
        
        #stop = timeit.default_timer()
        #print('Time: ', stop - start)
        
        tmp = self.eventi[sim_time]
        next_events = []
        
        
        #start = timeit.default_timer()
        for event in tmp:
            if event.what == 'LC_idle':
                next_events.append(event)
                
        for event in tmp:
            if event.what == 'RX':
                next_events.append(event)
                
        #stop = timeit.default_timer()
        #print('Time: ', stop - start)
        
        return next_events
    
    def sim_status(self):
        if len(self.eventi.keys()) == 0:
            return False
        else:
            return True	


#Parte del Sagomatore

def extractUpperBound(val_real, val_pred, start_x, parallel_slope):
    diff = val_real - val_pred
    #Extract max differences its index
    ind = np.argmax(diff)
    #Retrieve x and y
    x_ = start_x[ind][0]
    y_ = val_real[ind]
    
    #Compute b for the parallel line
    
    b_ = y_ - x_*parallel_slope
    
    return b_[0], y_

def Sagomatore_Analysis(df, modello, title):
    
    if df.shape[0] > 0:
    
        #Dataframe selected according to the DSCP
        
        #Transform datetime data considering only the part after the point
        #df['time'] = df['time'].map(lambda x: float(x.split()[0][6:]))
        df['time'] = df['time'].map(lambda x: float(x.split()[0][9:]))
        
        
        unit_time = len(str(df.iloc[0]["time"]))
        #print("Unit Time")
        #print(unit_time)
        
        #Length data into int
        df['length'] = df['length'].map(lambda x: int(x))
        #print("Max Pacchetto")
        #print(max(df["length"]))
        
        #Shift value with time that will go from 0 to max(time) - min(time)
        shifting_value = min(df["time"])
        df['time'] = df['time'].map(lambda x: x - shifting_value)
        
        
        # Plot x = Time - y = Comulative Byte
#        plt.scatter(x = df["time"], y = np.cumsum(df["length"]), alpha=0.5)
#        plt.title('Comulative Byte of Non Best Effort Traffic')
#        plt.xlabel('Time')
#        plt.ylabel('Comulative Byte')
#        #plt.xticks([])
#        #plt.set_yscale('log')
#        yticks = (np.arange(0, 500000, step=50000))
#        plt.yticks(yticks)
#        plt.show()
        
        
        #Linear REGRESSION Part
        
        x = np.array(df["time"]).reshape((-1,1))
        y = np.array(np.cumsum(df["length"]))
        
        model = LinearRegression()
        
        model.fit(x, y)
        
        #Model Result
        
        #R^2
        #r_sq = model.score(x, y)
        #print('coefficient of determination:', r_sq)
        
        #m
        #print('slope:', model.coef_)
        slope = model.coef_
        
        #b
        #print('intercept:', model.intercept_)
        intercept = model.intercept_
        
        #Prediction with our model
        Y_pred = model.predict(x)
        
        #ci = 100000 * np.std(Y_pred)/np.mean(Y_pred)
        
        #Intercetta dell'Upper Bound e valore massimo di yByte
        b, upper_y = extractUpperBound(y, Y_pred, x, slope) 
        
        #print(b)
        #print(upper_y)
    
        
    
        #Plot Figure with our prediction and the Upper Bound
        
        #Reinserire dopo le simulazioni
        
        
#        plt.figure(figsize=(10,8))
#    
#        #Real data
#        plt.scatter(x, y, s = 5)
#        #Predition LR model
#        plt.plot(x, Y_pred, color='red')
#        
#        #Upper Bound
#        plt.plot(x, x*slope + b, color='red')
#        
#        plt.fill_between(np.array(df["time"]),(x.reshape((len(x),))*slope[0] + b), (Y_pred), color='r', alpha=.1)
#        plt.title("Comulative Byte of  " + title + "  Traffic")
#        plt.xlabel('Time')
#        plt.ylabel('Comulative Byte')
#        plt.ticklabel_format(style = "sci", scilimits= (4,4), axis = "both")
#       
#        plt.savefig("Prova" + title + ".png", dpi = 200)
#        plt.show()
        
        #DEFINIRE COSA ESTRARRE
        
        if modello == "LR":
            #print(unit_time)
            #Unit time used to have bandwidth ad Byte/sec
            
            #if intercept < 0:
                
                #Nel caso in cui il modello ci consigliasse un valore negativo per il buffer
                # prendiamo il valore di massima lunghezza del pacchetto
                #intercept = max(df["length"])
                
                
            intercept = max(intercept, max(df["length"])) + max(df["length"])
            
            #print(intercept, max(df["length"]))
            #input()
            return slope[0]*8, intercept*8, True
            #return slope[0]*8, int(slope[0]*8*0.250/65), True
            
        elif modello == "UB":
            
            intercept = max(b, max(df["length"])) + max(df["length"]) 
            
            #print(intercept, max(df["length"]))
            
            return slope[0]*8, intercept*8, True
            #return slope[0]*8, int(slope[0]*8*0.250), True
    else:
        print("Dataset Vuoto")
        
        return 0,0, False 



def dictionaryUpdate(dizionario, classe, codice, buffer, banda):
    
    #Aggiunta di 1 classe DSCP
    dizionario[classe] = {}
    
    #Codice DSCP
    dizionario[classe]["codice"] = codice
    
    #Len_Buffer
    dizionario[classe]["buff_len"] = math.ceil(buffer)
    
    #Banda
    dizionario[classe]["reserved_bandwidth"] = math.ceil(banda)
    
    return dizionario


def dictionaryCreation(data_analysis, modello_type, labelDSCP, codiceDSCP, dizionarioParametri):
    
    banda,buffer,check = Sagomatore_Analysis(df = data_analysis,   modello = modello_type, title = labelDSCP)
    
    if check:
        dizionarioParametri = dictionaryUpdate(dizionarioParametri, 
                                               labelDSCP, codiceDSCP, buffer,
                                               banda)
		
    return dizionarioParametri


