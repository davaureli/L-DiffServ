# L-DiffServ

This code is related to the paper titled "Going Beyond DiffServ in IP Traffic Claasification" under consideration for publication. 
For more information please contact me.

### List of Files:

*1 - get_Data_from_Mawi.py* : This file downloads the traces from the cite http://mawi.wide.ad.jp/mawi/samplepoint-F/2019/ specifying the                                 date.

*2 - Main.py*: This file works the trace by extracting the information from each packte to create the dataframe.

*3 - Functions.py*: This file contains the functions imported from the Main.py

*4 - Clustering.py*: This file applies data preparation to the beginning dataframe. Then determines the new number of service classes using                      K-Means & Silhouette Coefficient.

*5 - Functions_Clustering.py*: This file contains the functions imported from the Clustering.py





