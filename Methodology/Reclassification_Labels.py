# -*- coding: utf-8 -*-
"""
Created on Wed May 22 10:57:45 2019

@author: Davide
"""

# =============================================================================
# In this part of the work, we'll try to Classify correctly our new Dataset 
# (with the new labels); finding the optimal algorithm for our porpuse. 
# After that, we can try to classify a new trace of packets using this method.
# =============================================================================

import pickle
import pandas as pd
import numpy as np
import os
import operator

from Functions_Multiclassification import *

#Download the new dataframe created after the K-Means
new_dataframe = pd.read_pickle("NewDataFrame.pkl")
new_dataframe.head()

#Open the new priority created by the K-Means
with open('../simulator/Priority.pkl', 'rb') as handle:
    priority = pickle.load(handle)

wdr = "MultiLabels Classification"

try:  
    os.mkdir(wdr)
except OSError:  
    print ("Creation of the directory %s failed" % wdr)
else:  
    print ("Successfully created the directory %s " % wdr)

print()
print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
print()

#Now we have to change this path and enter in our new folder
os.chdir('./' + wdr)
print("This is the NEW  cwd:  " + os.getcwd())
print()
    

#The order of the dictionary do not reflect the priority 
#But is useful for the classification labels in our problem

labels = {}
for key in priority:
    for elem in priority[key]:
        labels[elem[0]] = key


#Insert label in a list in the specific position of the Label after K-Means
tag = []
for pos in labels:
    tag.insert(pos, labels[pos])
    
#Colors 
    
cc ={'AF': "Black",
     'Critical voice RTP':"Red",
     'Network or Intenetwork control':"Blue",
     'Not Known':"Yellow",
     'best effort':"Green"}

list_colors = []
for i in labels:
    list_colors.insert(i,cc[labels[i]])

'''
Parte commentata giovedì mattina per vedere i risultati della classificazione

#Evaluating the Behavior on a single attempt, dividing data in train and test
MultiClassification(data = new_dataframe, x_components = 2, etichetta = tag, col = list_colors)

#K-Fold Cross Validation
diz_acc, diz_F1 = Validation(data = new_dataframe, x_components = 2)

#Printing the results obtined in each algorithm
for k in diz_F1:
    print()
    print(k)
    print()
    print("F-1 Score of : " + str(sum(diz_F1[k])/len(diz_F1[k])))
    print()
'''

optimal_parameters_gridsearch, diz_result_gridsearch = GridSearch(data = new_dataframe, x_components = 3)



#Once we have extracted all the results from the possible algorithm we will choose
# the best one from the dictionary 

#Extract the optimal values from the dictionary diz_result_gridsearch according to the recall
opt_algo = max(diz_result_gridsearch.items(), key=operator.itemgetter(1))[0]

#Extract the optimal parameters after having evaluate the optimal algo
opt_parameters = optimal_parameters_gridsearch[opt_algo]
#The following change in the dict is necessary to evaluate the pipeline again through GridSearch
#it needs of a list of elements and not ongly a string
opt_parameters = {k : [i] for k,i in opt_parameters.items()}
#We have to create the model and save it into the Test_Classification folder

save_optimal_model(data = new_dataframe, x_components = 3, algorithm = opt_algo, parameters = opt_parameters)

print()
print("Here we saved the new model for the classification !!!") 
print()
print("Finish this part !!!")
