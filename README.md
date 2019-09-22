# L-DiffServ

This code is related to the paper titled "Going Beyond DiffServ in IP Traffic Claasification" under consideration for publication. 
For more information please contact me.

### List of Files:

1) **get_Data_from_Mawi.py** : This file downloads the traces from the cite http://mawi.wide.ad.jp/mawi/samplepoint-F/2019/ specifying the                                 date.

2) **Main.py** : This file works the trace by extracting the information from each packte to create the dataframe.

3) **Functions.py**: This file contains the functions imported from the Main.py

4) **Clustering.py**: This file applies data preparation to the beginning dataframe. Then determines the new number of service classes                           using K-Means & Silhouette Coefficient. Here we determine our classification: *L-DiffServ*

5) **Functions_Clustering.py**: This file contains the functions imported from the Clustering.py

6) **Reclassification_Labels.py**: This file adds the new labels (*L-DiffServ*) to the starting dataframe according to the classification algorithm selected.

7) **Functions_Multiclassification.py**: This file contains the functions imported from the Reclassification_Labels.py

8) **Simulation_MAM_L_DiffServ**: This files simulates the MAM (maximum allocation model) with setting of Cisco and Traffic Based for resource distribution; evaluating current classification and our L-DiffServ.

9) **Simulation_RDM_L_DiffServ**: This files simulates the RDM (russian doll model) with setting of Cisco and Traffic Based for resource distribution; evaluating current classification and our *L-DiffServ*.

Finally the *.pcap files* could be used to practice our work.





