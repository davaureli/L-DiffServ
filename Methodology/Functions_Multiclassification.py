# -*- coding: utf-8 -*-
"""
Created on Wed May 22 11:06:06 2019

@author: user
"""
# =============================================================================
# FUNCTIONS for Classify NewLabels
# =============================================================================

import os
import matplotlib.pyplot as plt
import numpy as np
import itertools
#Classification Libraries
from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

#Plot the confusion Matrix
#from sklearn.utils.multiclass import unique_labels
from matplotlib.colors import ListedColormap
from sklearn.metrics import confusion_matrix

#K fold cross validation and Grid Search using the Pipeline
from imblearn.pipeline import make_pipeline
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import GridSearchCV

#Evaluation metrics
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score
from sklearn.metrics import make_scorer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

import pickle

#col = utilizzato per i plot di Train e test
#per ora i colori sono quelli utilizzati nel K-Means
def MultiClassification(data, x_components, etichetta, col):
    
    # X -> features, y -> label
    if x_components == 3:
    
        X = data.iloc[:, :3].values
        y = data.iloc[:, -1].values

    elif x_components == 2:
    
        X = data.iloc[:, :2].values
        y = data.iloc[:, -1].values
    
    # Dividing X, y into train and test data 
    
    #Test size di Default è 0.25
    X_train, X_test, y_train, y_test = train_test_split(X, y, random_state = 42 ) 
  
    print()
    print("Possible algorithms about Classification Problem: ")
    print()
    
    #VM
    #Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", 
    #           "Random Forest", "XGBoost"]
    
    #LOCAL
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", 
             "Random Forest"]
    print(Ml_Algo)
    
    #We will evaluate the result of the confusion matrix for all the possible algorithms
    
    # Fitting classifier to the Training set
    
    for i in Ml_Algo:
        method = i
        
        print()
        print("You have choose this ML Method : " + method)
        print()
        
        #Creation of a Directory for each possible Classification method 
        
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)
    
        if method == "Logistic" :
        
            
            classifier = LogisticRegression(random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "SVM con Kernel":
            
            # Fitting Kernel SVM to the Training set
            classifier = SVC(kernel = 'rbf', random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Naive Bayes":
            
            # Fitting Naive Bayes to the Training set
            classifier = GaussianNB()
            classifier.fit(X_train, y_train)
        
        elif method == "Decision Trees":
            
            # Fitting Decision Tree Classification to the Training set
            classifier = DecisionTreeClassifier( random_state = 0)
            classifier.fit(X_train, y_train)
        
        elif method == "Random Forest":
            
            # Fitting Random Forest Classification to the Training set
            classifier = RandomForestClassifier(random_state = 0)
            classifier.fit(X_train, y_train)
            
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0)
            classifier.fit(X_train, y_train)
        
        # Predicting the Test set results
        y_pred = classifier.predict(X_test)
        
        # Making the Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        
        print()
        print("We obtained this result, Confusion Matrix: ")
        print(cm)
        print()
        
# =============================================================================
#                          PLOT CONFUSION MATRIX
# =============================================================================
        
        print("Confusion Matrix Not Normalized")
        plot_confusion_matrix_2(cm = cm,
                      target_names = etichetta ,
                      method = method ,
                      title='Confusion matrix',
                      cmap=None,
                      normalize=False,
                      directory = nn_dir
                      )
        
        print()
        print("Confusion Matrix Normalized")
        print()
        
        plot_confusion_matrix_2(cm = cm,
                      target_names = etichetta ,
                      method = method ,
                      title='Confusion matrix',
                      cmap=None,
                      normalize=True,
                      directory = nn_dir
                      )
        print("Finish the anlysis of the Confusion matrix")
        print()
        
        print("Saving the confusion matrix if we want to see in detail the results")
        np.save("./" + nn_dir + "/ConfusionMatrix_using_" + method, cm)
        
        #Evaluating the Accuracy result
        accuracy = accuracy_score(y_test, y_pred)
        print("This is the Accuracy score: " + str(round(accuracy,2)*100) + "%")
        print()
        
        report = classification_report(y_test, y_pred)
        print("This is the report")
        print(report)
        print()
        
        #precision = precision_score(y_test, y_pred)
        #print("The precision is: " + str(precision))
        
        #recall = recall_score(y_test, y_pred)
        #print("This is the recall score: " + str(recall))
        
        # Visualising the TRAINING set results
        '''
        X_set, y_set = X_train, y_train
        
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
     
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, colors = col)
        
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = col[i], label = j)
        plt.title('Classifier (Training set) using: ' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of training with " + method + ".png", dpi = 150, figsize=(12,6))
        plt.show()
        #plt.close()
        '''
        # Visualising the TEST set results
        
        X_set, y_set = X_test, y_test
        X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                             np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
        plt.contourf(X1, X2, classifier.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
                     alpha = 0.75, colors = col)
        plt.xlim(X1.min(), X1.max())
        plt.ylim(X2.min(), X2.max())
        for i, j in enumerate(np.unique(y_set)):
            plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
                        c = col[i], label = j)
        plt.title('Classifier (Test set) using' + method)
        
        ##il pre_var esce dal risultato della PCA prenderlo da lì, si capisce meglio da
        ##Balancing_DataSet.py
        
        #plt.xlabel("PC1 - {0}%" .format(pre_var[0]))
        #plt.ylabel("PC2 - {0}%" .format(pre_var[1]))
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.savefig("./" + nn_dir + "/Classification of test with " + method + ".png", dpi = 150, figsize=(12,6))
        plt.show()
        #plt.close()
    
        print("Finish the first attempt of classifciation")
        
# =============================================================================
# K-fold Cross Validation
# =============================================================================
        
        
        
def Validation(data, x_components):
    
    # Applying k-Fold Cross Validation using a Pipeline
    #L'idea sarà quella di riprendere il dataset iniziale, bilanciarlo attraverso 
    #Under e Oversampling.
    #A quel punto suddividerlo in 10 cartelle e osservare i risultati che otteniamo di 
    #Accuracy.
    #Ricordanto che le cartelle saranno stratificate ovvero manterranno la stessa percentuale 
    #di occorrenze tra Best e Non Best Effort.
    
    dd_r = "K-Fold Cross Validation"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
    print()
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print("Starting Cross Validation !!!!")
    
    #Definition of the passages into the Pipeline
     
    # Make the splits
    n = 13
    kf = StratifiedKFold(n_splits = n, random_state = 0)
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    print()
    print("Possible algorithm about Classification Problem: ")
    
    #Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees", "Random Forest",
      #        "XGBoost"]
    
    Ml_Algo = ["Logistic", "SVM con Kernel", "Naive Bayes", "Decision Trees",
               "Random Forest"]
    
    print(Ml_Algo)
    print()
    
    tot_acc={ j:[] for j in Ml_Algo}
    tot_F1={ j:[] for j in Ml_Algo}
    
    #Loading Data according to the specified Principal Components
    
    if x_components == 3:
        
        X = data.iloc[:,:3].values
        y = data.iloc[:,-1].values
        
    elif x_components == 2:
        X = data.iloc[:,:2].values
        y = data.iloc[:,-1].values
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
            
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)
    
    # Possible methods
    
        if method == "Logistic" :
            
            classifier = LogisticRegression(random_state = 0, n_jobs = -1)
            
        elif method == "SVM con Kernel":
            
            classifier = SVC(kernel = 'rbf', random_state = 0)
            
        elif method == "Naive Bayes":
            # Fitting Naive Bayes to the Training set
            
            classifier = GaussianNB()
            
        
        elif method == "Decision Trees":
            
            #classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
            classifier = DecisionTreeClassifier(random_state = 0)
        
        elif method == "Random Forest":
            
            #classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 0)
            classifier = RandomForestClassifier( random_state = 0, n_jobs = -1)
            
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0, n_jobs = -1)
            
            
        print("Start the PIPELINE !!!")
        
        # Add one transformers and two samplers in the pipeline object
        pipeline = make_pipeline(classifier)

        print()
        print(" Starting CROSS-Validation, with k = 10 folds, with this method: " + method)
        print()
            
        
    #If it is not clear review the link from Stack
    #https://stackoverflow.com/questions/48370150/how-to-implement-smote-in-cross-validation-and-gridsearchcv
        
        for train_index, test_index in kf.split(X,y):
            #print("TRAIN:", train_index, "TEST:", test_index)
            
            X_train, X_test = X[train_index], X[test_index]
            y_train, y_test = y[train_index], y[test_index]
            
            #print("Start Working")

            pipeline.fit(X_train, y_train)
       
            y_hat = pipeline.predict(X_test)
           
            # Making the Confusion Matrix
            
            #print()
            #cm = confusion_matrix(y_test, y_hat)
            #print(cm)
            #print()
            accuracy = accuracy_score(y_test, y_hat)
            #Inserire il numero del cluster relativo a quelli Non Best Effort
            
            ##### ATTENZIONE CAMBIARE QUESTI VALORI QUI DENTRO !!!!! #####
            
            F1 = f1_score(y_test, y_hat, labels = [4,5,9,11,1,3,7,8,10], average=None)
            #print(accuracy)
            
            tot_acc[method].append(accuracy)
            tot_F1[method].append(F1)
    
    print()
    print("ACCURACY Results")
    print()
    print("Results: ")
    tot_acc = {k:sum(tot_acc[k])/len(tot_acc[k])for k in tot_acc} 
    print()
    print(tot_acc)
    
    print()
    print("F1_Score")
    print()
    print("Results: ")
    tot_F1 = {k:sum(tot_F1[k])/len(tot_F1[k])for k in tot_F1} 
    print()
    print(tot_F1)
    print()
    
    #Now we have to change this path and enter in our new folder
    os.chdir('../')
    print("This is the NEW  cwd:  " + os.getcwd())
    print(" Finish Cross Validation !!!! ")
    
    return  tot_acc, tot_F1    
        
            
# =============================================================================
#             print()
#             print(accuracies)
#             print()
#             print("The Accuracy mean is about : " + str(round(accuracies.mean(),2)*100) + "% using " + method)
#             print("The sd of the Accuracy is : " +str(round(accuracies.std(),2)*100)+ "% using " + method)
#             print()
# =============================================================================
            
###SI PUò INSERIRE LO SCATTER PLOT DELLE ACCURATEZZE
## VEDERE IL LINK
#https://machinelearningmastery.com/compare-machine-learning-algorithms-python-scikit-learn/


def GridSearch(data, x_components):
    
    dd_r = "Grid Search"
    
    try:  
        os.mkdir(dd_r)
    except OSError:  
        print ("Creation of the directory %s failed" % dd_r)
    else:  
        print ("Successfully created the directory %s " % dd_r)
    print()
    print("This is the cwd:  " + os.getcwd()) # Prints the current working directory
    print()

    #Now we have to change this path and enter in our new folder
    os.chdir('./' + dd_r)
    print("This is the NEW  cwd:  " + os.getcwd())
    print()
    print("Starting Grid Search !!!!")
    print()
    
    #Definition of the passages into the Pipeline
    
    # Make the splits
    n = 13
    kf = StratifiedKFold(n_splits = n, random_state = 0)
    
    #method = input(" Choose your ML method for this Classifictaion Problem: ")
    #print("You have choose this ML Method for your classification problem: " + method)
    
    # Fitting classifier to the Training set
    
    print()
    print("Possible algorithm about Classification Problem: ")
    
    Ml_Algo = [ "Random Forest"]
    #Ml_Algo = ["Logistic", "Random Forest"]
    print(Ml_Algo)
    print()

    if x_components == 3:
        
        X = data.iloc[:,:3].values
        y = data.iloc[:,-1].values
        
    elif x_components == 2:
        X = data.iloc[:,:2].values
        y = data.iloc[:,-1].values
    
    val = {}
    result_algo = {} 
    
    for i in Ml_Algo:
        method = i
        print("You have choose this ML Method for your classification problem: " + method)
        print()
        #Fitting Logistic Regression to the Training set
        
        nn_dir = method
        try:  
            os.mkdir(nn_dir)
        except OSError:  
            print ("Creation of the directory %s failed" % nn_dir)
        else:  
            print ("Successfully created the directory %s " % nn_dir)
    
        if method == "Logistic" :
            
            classifier = LogisticRegression(random_state = 0, n_jobs = -1)

            # Create regularization penalty space
            penalty = ['l1', 'l2']
        
            # Create regularization hyperparameter space
            #C = np.logspace(0, 4, 10)
            C = [ 0.001, 0.0001, 0.0001]
            
            # Create hyperparameter options
            parameters = {"logisticregression__C":C, "logisticregression__penalty":penalty}
            
        elif method == "SVM":
            
            classifier = SVC(random_state = 0)
            
            #0.01,0.001,0.0001
            parameters = {'svc__kernel': [ "rbf"], 'svc__gamma': [1e-3],
                          'svc__C': [ 1]}
                        
        
        elif method == "Random Forest":
            
            classifier = RandomForestClassifier( random_state = 0, n_jobs = -1)
            
            #we exclude the entropy criterion (or Information gain) cause they are 
            #very similar; usually it is suggested the Gini Impurity cause is less
            #computational expensive 
            
            parameters = {'randomforestclassifier__n_estimators': [20, 21, 22],
                          'randomforestclassifier__criterion': ['gini'],
                          'randomforestclassifier__max_features': [None, "auto", "sqrt", "log2"]
                          }
        
        elif method == "XGBoost":
            
            #classifier = Boosting
            classifier = XGBClassifier(random_state = 0, n_jobs = -1)
            
            parameters = {"xgbclassifier__max_depth":[3,5,7],
                          "xgbclassifier__gamma":[0, 0.1, 0.2],
                          "xgbclassifier__colsample_bytree":[0.5,0.6,0.7],                
                          "xgbclassifier__n_estimators": [10, 100, 500],
                          "xgbclassifier__learning_rate": [0.1, 0.5, 1],
                          'xgbclassifier__min_child_weight': [1, 3, 5]
                          
                    }
            
            
        print("Start PIPELINE !!!")
        
        # Add one transformers and two samplers in the pipeline object
        pipeline = make_pipeline(classifier)
        #pipeline = make_pipeline(knn)
        print()
        print(" Starting Grid Search, with this method: " + method)
        print()
            
        
    #If it is not clear review the link from Stack
    #https://stackoverflow.com/questions/48370150/how-to-implement-smote-in-cross-validation-and-gridsearchcv
        
        scorers = {
                'precision_score': make_scorer(precision_score, average= "micro"),
                'recall_score': make_scorer(recall_score, average= "micro"),
                'accuracy_score': make_scorer(accuracy_score),
                'f1_scorer': make_scorer(f1_score, average= "micro")
            }
        
        random_search = GridSearchCV(pipeline,  param_grid = parameters , cv = kf,  scoring = scorers, refit = 'recall_score')
        gg = random_search.fit(X, y)
        #a = gg.cv_results_
        #print(a)
        #print(gg.best_estimator_)
        print(gg.best_params_)
        print()
        print(gg.best_score_)
        print()
        #Appending the optimal parameters 
        val[i] = gg.best_params_
        #Appending the result obtained using a specific algorithm
        result_algo[i] = gg.best_score_
        
    #Printing the results
    print(val)
    print()
    print(result_algo)
    return val, result_algo


def save_optimal_model(data, x_components, algorithm, parameters):
    
    #Definition of the passages into the Pipeline
    
    # Make the splits
    n = 13
    kf = StratifiedKFold(n_splits = n, random_state = 0)
    
    print(algorithm)

    if x_components == 3:
        
        X = data.iloc[:,:3].values
        y = data.iloc[:,-1].values
        
    elif x_components == 2:
        X = data.iloc[:,:2].values
        y = data.iloc[:,-1].values
        
    if algorithm == "Logistic" :
        
        classifier = LogisticRegression(random_state = 0, n_jobs = -1)
        
    elif algorithm == "SVM":
        
        classifier = SVC(random_state = 0)
        
   
    elif algorithm == "Random Forest":
        
        classifier = RandomForestClassifier( random_state = 0, n_jobs = -1)
        
    
    elif algorithm == "XGBoost":
        
        #classifier = Boosting
        classifier = XGBClassifier(random_state = 0, n_jobs = -1)
        
        
    print("Start PIPELINE !!!")
    
    # Add one transformers and two samplers in the pipeline object
    pipeline = make_pipeline(classifier)
    
    scorers = {
        'precision_score': make_scorer(precision_score, average= "micro"),
        'recall_score': make_scorer(recall_score, average= "micro"),
        'accuracy_score': make_scorer(accuracy_score),
        'f1_scorer': make_scorer(f1_score, average= "micro")
    }

    
    random_search = GridSearchCV(pipeline,  param_grid = parameters , cv = kf,  scoring = scorers, refit = 'recall_score')
    model = random_search.fit(X, y)
    
    print("We are saving the model")
    # save the model to disk
    filename = '../../Test_Classification/classification_model.sav'
    pickle.dump(model, open(filename, 'wb'))
    print()
    print("We have finished: MODEL SAVED")
    


### Functon to plot the confusion matrix 
### This fuction is recalled by the evaluation made between all
### possible algorithms
    
def plot_confusion_matrix_2(cm,
                            directory,
                            method,
                            target_names, 
                            title='Confusion matrix',
                            cmap=None,
                            normalize=True):
    FONT_SIZE = 10
    
    accuracy = np.trace(cm) / float(np.sum(cm))
    misclass = 1 - accuracy
    
    if cmap is None:
        cmap = plt.get_cmap('Blues')
    
    plt.figure(figsize=(8*2, 6*2))    # 8, 6
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    
    if target_names is not None:
        tick_marks = np.arange(len(target_names))
        plt.xticks(tick_marks, target_names, rotation=90, fontsize=FONT_SIZE)
        plt.yticks(tick_marks, target_names, fontsize=FONT_SIZE)
    
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    
    
    thresh = cm.max() / 1.5 if normalize else cm.max() / 2
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        if normalize:
            plt.text(j, i, "{:0.4f}".format(cm[i, j]),
                     horizontalalignment="center",
                     fontsize=FONT_SIZE,
                     color="white" if cm[i, j] > thresh else "black")
        else:
            plt.text(j, i, "{:,}".format(cm[i, j]),
                     horizontalalignment="center",
                     fontsize=FONT_SIZE,
                     color="white" if cm[i, j] > thresh else "black")
    
    
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label\naccuracy={:0.4f}; misclass={:0.4f}'.format(accuracy, misclass))
    if normalize:
        plt.savefig("./" + directory + "/ConfusionMatrix_Normalize_using_" + method + ".png")
    else:
        plt.savefig("./" + directory + "/ConfusionMatrix_using_" + method + ".png")
    #plt.show()
    plt.close()
