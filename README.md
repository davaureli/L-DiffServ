# L-DiffServ & Packet Based Simulator

This work is related to the paper titled **Going Beyond DiffServ in IP Traffic Classification** published in *NOMS 2020-2020 IEEE/IFIP Network Operations and Management Symposium. IEEE, 2020*. Now the development related to the simulator code is related to another paper under consideration for publication. 
For more information please contact me.

### Methodology

1) **get_Data_from_Mawi.py** : This file downloads the traces from the cite http://mawi.wide.ad.jp/mawi/samplepoint-G/2019/ specifying the                                 date.

2) **Main.py** : This file works the trace by extracting the information from each packte to create the dataframe.

3) **Functions.py**: This file contains the functions imported from the Main.py

4) **Clustering.py**: This file applies data preparation to the beginning dataframe. Then determines the new number of service classes                           using K-Means & Silhouette Coefficient. Here we determine our classification: *L-DiffServ*

5) **Functions_Clustering.py**: This file contains the functions imported from the Clustering.py

6) **Reclassification_Labels.py**: This file adds the new labels (*L-DiffServ*) to the starting dataframe according to the classification algorithm selected.

7) **Functions_Multiclassification.py**: This file contains the functions imported from the Reclassification_Labels.py


### sim

1) **Simulator_BE_L-DiffServ.py**: The file is the main for the spacket based simulator.

2) **Functions_Simulator_L-DiffServ.py**: This file contains all classes for the simulator.

### data_pcap

1) *.pcap files* could be used to practice our work.





