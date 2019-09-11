# Going Beyond DiffServ in IP Traffic Classification

As the number of Internet users continues to grow, network performance requirements must increase right along with them. In addition, many of the latest online services require high network performance.The primary goal of quality of service is managing resources by setting priorities for speciﬁc types of data (video, audio, ﬁles). Actually packets are classified through DiffServ architecture based on the **RFC 4594**. So, there are features which identify packets from a particular service class. In this project, we propose a methodology able to detect these distinctive characteristics to improve the granularity of service classes. In fact, the idea is to establish the new number of services through a sub-classiﬁcation starting from the macro service classes. The evaluation between the different classiﬁcation methods, the current one and the proposed one, takes place through a simulation testing the behaviour of the network during congestion; considering the percentage of ﬂows hit by packet loss. We validate the approach on the **MAWI** data set. We analyze the model conditions which favor our classification with respect to the current one and vice versa.

### Introduction

The capability to provide resource assurance and service differentiation in a network is referred to as Quality of Service (QoS). Resource assurance is critical for new applications to ﬂourish and prosper, moreover the Internet will become a truly multiservice network only improving service differentiation. One of the core building blocks for enabling QoS is represented by Differentiated Services (DiffServ). This architecture manages the problem related to resource allocation; packets get dropped or delayed because the resources in the network cannot meet all the trafﬁc demands. This service model was proposed to overcome the Integrated Services [2] architecture (IntServ), a ﬁrst attempt made by IETF to ensure QoS, based on per-ﬂow resource reservation. Flow-based algorithms have the ability to offer a good quality of service to one or more ﬂows because they reserve all the necessary resources along the way but this approach is not well suited for systems where thousands or millions of ﬂows circulate. In addition, routers maintain an internal state for each ﬂow, which makes them vulnerable to router failures. The IETF therefore turned to a simpler approach aimed at quality of service, which could be implemented mostly locally in each router, without involving the entire path. This system (DiffServ) is based on classes as opposed to IntServ based on ﬂows. The trafﬁc injected by the user into the network is mapped by the edge routers into the appropriate forwarding classes. The forwarding class is directly encoded into the packet header. This information is used by the interior nodes of the network to differentiate the treatment of the packets, because the forwarding classes may indicate drop priority or resource priority. In this paper, we propose a methodology able to improve the quality of service for what it concerns packets loss. Our idea is to propose a different classiﬁcation, starting from the current one, we want to increase the granularity of the macro service classes. For the evaluation, we use the MAWI dataset, containing daily trafﬁc traces of a transpaciﬁc backbonelink,weobservethebehaviourofthenetworkduring congestion in the MAM and RDM model, analysing which classiﬁcation obtains better results.

### DiffServ Architecture

DiffServ architecture was proposed by the IETF publishing RFC 2474 [3]. It relies on a mechanism to classify and mark packets as belonging to a speciﬁc class of service, using 8 bits for the Differentiated Services (DS) ﬁeld in the IP header. This ﬁeld is composed by two components, the 6 most signiﬁcant bits identify the DSCP (Differentiated Services Code Point) while the 2 least signiﬁcant bits deﬁne the ECN (Explicit Congestion Notiﬁcation). Classiﬁcation is based only on the DSCP ﬁeld, while the ECN ﬁeld is used for router communication in congestion detection. Each router is conﬁgured to differentiate trafﬁc based on its set of classes. Each trafﬁc class can be managed differently, ensuring preferential treatment for higher-priority trafﬁc. In DiffServ complex functions, such as packet classiﬁcation, can be carried out at the edge of the network by edge routers. Whereas core routers simply apply per-hop behaviour treatment (PHB) which deﬁnes the packet forwarding properties associated to a speciﬁc trafﬁc class. In theory, a network could have up to 64 different trafﬁc classes using the 64 available DSCP values, this gives to the network operator great ﬂexibility. In practice DiffServ recommend, but do not require, certain encodings. Most networks use the following commonly PHB:

- Default Forwarding (DF) -- best effort traffic;
- Expedited Forwarding (EF) -- low loss, low latency traffic;
- Assured Forwarding (AF) -- assurance of delivery under prescribed conditions;
- Class Selector (CS) -- backward compatibility with IP precedence field.

### Machine Learning Techniques

<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/diagramma.png" width="600">
 </p>
 
* Data Description 
  
The WIDE project provides researches with daily traces of a transpaciﬁc link, called the MAWI Archive [1]. Each ﬁle contains 15 minutes of trafﬁc ﬂows, captured between 14:00:00 and 14:15:00 local time. This represents usually between 4 and 15 GB of trafﬁc for one ﬁle. Before being released, traces are anonymized so that no personal information can be extracted. Speciﬁcally, the application data is removed and IP addresses are scrambled with the Crypto-PAn Algorithm [11], following these principles: collision-free and preﬁx-preserving. In our analysis we work on the trace of Thursday 7th March, 2019, the ﬁle size is 6696.53 MB and the number of packets is 99,710,343; the channel is used with an average of 688.18 Mbps and a standard deviation of 207.01 Mbps. In the trafﬁc analysis, we work only with Ipv4 packets considering one direction of the ﬂow by ﬁltering packets through the MAC address; this choice has been taken into account for the ﬁnal unidirectional trafﬁc simulation. So, we consider a small part of the total trace, 2,501,286 packets, both for work choices and for memory limits.

The following characteristics are the features extracted from every packet: Internet Header Length (IHL), Differentiated Services Code Point (DSCP), Explicit Congestion Notiﬁcation (ECN), Total Length, Flags, Fragment Offset, Time To Live (TTL), Protocol, Source address, Destination address and from the TCP layer we extract Source Port and Destination Port. In the Table I we conclude the data description reporting the mapping between the DSCP value and the service class name; we use them during the analysis as packets’ label.

| DSCP Value  | DSCP Class | DSCP Label |
| ------------- | ------------- |------------- |
| 48, 56  | C6 C7  | Network & Internetwork Control  |
| 40, 46  | CS5 EF  | Critical Voice RTP  |
| 32, 34, 36, 38  | CS4 AF4  | Flash Ovrride  |
| 24, 26, 28, 30  | CS3 AF3  | Flash Voice  |
| 16, 18, 20, 22 | CS2 AF2  | Immediate  |
| 8, 10, 12, 14  | CS1 AF1  | Priority  |
| 0  |CS0  | Best Effort  |

Observing the column Class Label, is clear that we unify the CS class of service both with the AF and with EF because there are few observation for the backward compatibility classes.

* Pre Processing 

We create the dataset composed by the information for each packet with the DSCP marking as label. We need to clean the features to detect which variables most differentiate the trafﬁc. We decide not to consider, so delete, the features with zero variance because they are not signiﬁcantly important for packets differentiation. These variables are: Internet Header Length (IHL), Flags except for the DF ﬂag and Fragment Offset. Next we work on the four categorical variables, Source and Destination Address and Source and Destination Port. For the IP addresses, we try to reconstruct the association with the Autonomous System (AS) using the mapping code provided by [12]. However, [11] uses a different key for each day to anonymize the trace, so we cannot include IP addresses in our model. On the other hand, we can handle the Source and Destination Port. Our idea is to determine an identiﬁcation port for each packet, trying to maintain a high percentage of information. We see the port occurrences and then we maintain the ports that allow to keep 85% of information, while the remaining ports with a small percentage of occurrences are transformed into ports with 0 value. Moreover for the packets whose protocol has not deﬁned port, as ICMP packet, we assign the value −1; the value −1 and 0 have not a numerical importance but it affects the presence or the absence of such port within the packet. In this way we create the summary variable called Fundamental Port. Finally, in the data Pre Processing analysis we transform the categorical variables into binary variables while the numerical variables are normalized. For data normalization we use the MinMaxScaler function, with the following formula: 

(formula MINMAX SCALER)

However, until now, our methodology considers all packets in an undifferentiated way regarding the DSCP marking. But observing the occurrences of the service classes there is a great imbalance in favour of the 0 label (best-effort service). So, we apply the analysis for the Source and Destination Port and the normalization part splitting the beginning data frame into two components, the ﬁrst one composed by the besteffort data while in the other part we consider everything not marked as 0 for DSCP value. In this way we maintain the information related to the best-effort and non best-effort class, otherwise the few observation of the non best-effort classes could disappear under the magnitude of the best-effort packets. This last consideration opens the door to the main issue of our analysis, the unbalance. 

* Oversampling

We can observe the DSCP distribution of our trace. We focus the attention on the percentage of packets for each service class.

<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/distribution_DSCP.png" width="600">
 </p>

In the Figure 2 more than 98% of the trace is characterized by best-effort trafﬁc while for the other services the percentage is minimal or almost not existent. Moreover, in the histogram there is a label for Not Known marking, which is not listed in the Table I. During the explanation of the DiffServ architecture, suggested by the RFCs, we said that there are some values commonly used by the majority in the network to create a stable communication between different DiffServ Domains. However, in the analysis of the DSCP values comes out that there are values not recommended by the RFC and are almost all related to the values between 0 and 8. It is explained in the RFC 4594 [4] at pp20. This trafﬁc is known as Scavenger, something with lower priority than the best-effort class and to which is allocated the lowest amount of bandwidth; this argument will be resumed during the simulation part. Besides, it is interesting to observe the percentage of packets that belong to the other classes without considering the best-effort and Not Known occurrences, to have a complete picture of the information in our hands.


<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/distribution_DSCP_2.png" width="600">
 </p>

Observing the Figure 3 we have packets marked with the Expedited Forwarding (CS5, EF) class and Network & Internetwork Control (CS6 and CS7), while for the four Assured Forwarding (AF) classes we have almost no information. In fact the packets related to the Priority (CS1, AF1), Immediate (CS2, AF2), Flash Voice (CS3, AF3) and Flash Override (CS4, AF4) are only the 1.61% of the total number of packets (without considering best effort and Not Known class). This distribution of data presents one of the most discussed problems in the Machine Learning literature. The behaviour of the classiﬁcation algorithms when the dataset is strongly unbalanced in favour of a speciﬁc class. This problem is known as the Paradox of Accuracy. In fact, if we limit ourselves to identify best-effort packets from non best-effort, any classiﬁcation algorithm trained on this data will classify everything as best-effort getting always more than 90% of Accuracy. We decide to exploit the technique presented in [13]. Smote algorithm can oversample the service classes for which we have very few samples, without losing information from the best-effort class. We obtain a balanced dataset where each service class has the same number of occurrences of the best-effort class. Now we can extract the characteristics which maximize the differentiation between service classes.

*Dimensionality Reduction

The dataset after running the over-sampling technique has 10,611,286 number of rows, representing the packets , and 42 columns, as number of features (including the DSCP label). Our purpose is to extract the variables that most identify the belonging of a packet to one service class rather than to another. We reduce the dimensionality of the space working with the LDA (Linear Discriminant Analysis) technique. We choose this one because it allows us to specify the number of axes for the new space, thus obtaining a 3D graphic distribution of the packets. Moreover it works in a supervised way, being also a classiﬁcation algorithm, in this way it can maximize the variance between class of services. In the Table II are described the components of the 3 axis, created through LDA. For each initial variable we have the percentage amount of the correlation between it and the new axis. They are listed in a decreasing order considering only the magnitude of the percentage, we show only the ﬁrst ten components for each axis.

(Tabella assi di lda)

* Clustering

At this point, the dataset is projected into the new dimensional space deﬁned by LDA, the classiﬁcation part begins. We have to cluster packets even if they have already a label assigned. The purpose of our work is to increase the granularity of the current service classes. The starting point is the recommended classiﬁcation in RFC 4594 [4]. Below there is the summary of the available service classes, this represents the macro-classiﬁcation currently used for the DSCP marking.

- Best Effort (BE); 
- Not Known;
- Assured Forwarding (AF);
- Expidited Forwarding (EF);
- Network & Internetwork Control.

This list represents the current service demand, our working assumption is that if a class exists at the same time there is a demand to satisfy; so we cannot consider the possibility to decrease the service classes currently offered. The problem we are going to face is a problem of Clustering, where the data do not have a label and we cannot observe the correctness of the results obtained. However, it is essential to analyze the results according to an index of goodness about the clustering. Therefore, the fundamental tools are the clustering algorithm and the measure to evaluate the results. These tools lead us to determine the optimal number of centroids (k), which are the new available service classes. For the clustering algorithm we work with the wellknown K-Means [15], while for the evaluation index we use the Silhouette Coefﬁcient [17]. The Silhouette index is a measure of how similar a cluster is to its own cluster (Cohesion) compared to other ones (Separation). The Silhouette ranges from −1 to +1, where a high value indicates that the object is well matched to its own cluster and poorly matched to neighbouring clusters. The formula used to compute the Silhouette index is the following:

(Formula Silhouette)

e condizioni... 

We evaluate the optimal number of clusters (k), to establish the number of service classes for our ﬁnal proposal. The analysis considers a range of possible values, for k, from 5 to 75 with a step of 5. The following Figure 4 shows the results of the Silhouette Coefﬁcient.


<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/BarChartComparisonTipology.png" width="600">
 </p>

In each k we compute the Formula 2 by 100 times for each possible sample size, in this way we capture the real behaviour in our packets population without considering all the packets. In the Figure 4 we show the trend according to the variation of the sample size. At the beginning we have a dramatic increase for the Silhouette Index passing from 5 to 25 centroids. Then thereisaslowdecreaseuntil35centroidsandthenalittletrend of increase until 60 centroids, which represents the peak of our analysis, the last part is characterized by a steady decreasing trend. The choice of the optimal number of clusters takes into account both the maximization of the Silhouette Coefﬁcient and the greater variation between our choice and the value evaluated at the step before, for these reasons we prefer k = 25. Our evaluation reﬂects a conservative behaviour, knowing the disadvantages of the K-Means; especially the globular shape detecting for the clustering. In this way we can state that our classiﬁcation is composed by 25 Service Classes. In the Figure 5 we show the result of K-Means with 25 centroids; analyzing each cluster according to the Silhouette index.

<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/SilhouettePlot.png" width="600">
 </p>

In the upper plot, on the left side, the dot red line identiﬁes the average value between all the clusters for the Silhouette Coefﬁcient, equal to 0.88955. In the right side we have the legend related to the 3D-plot about K-Means clustering. In this legend we can see the sub-classes identiﬁed within the main classes. The best-effort class is differentiated into 11 sub-categories, while the Not Known service is divided into 7 different sub-classes. For both Assured Forwarding (AF) service class and Critical Voice RTP (EF) we see that our clustering algorithm ﬁnds only one subclass, without subdivisions.

* Classification

We can evaluate which classiﬁcation model obtains the best accuracy value; evaluating this performance on the trace that we use to create the new service classes. We consider three classiﬁcation algorithms: Multinomial Logistic Regression, SVM with Kernel and Random Forest. In the Table III we report the values of the grid search (best combination of the hyperparameters) and the relative accuracy value.

| Algorithm  | Hyperparameters | Accuracy Value |
| ------------- | ------------- |------------- |
| Multinomial Logistic Regression  |  C=0.001, penalty=’l1’ | 0.8525  |
| SVM with Kernel Trick  | C=1, gamma=0.001, kernel=’rbf’ | 0.9952  |
| Random Forest  | criterion=’gini’, maxfeatures=’auto’, n-estimators=21 | 0.9994  |
  
  Looking at the results of the Table III, we use Random Forest as algorithm to reclassify a generic trafﬁc trace according to our new service classes. 

### Numerical Analysis

In this section we evaluate our classiﬁcation respect to the current one, according to the behaviour of the network managing a congestion situation simulating real trafﬁc traces. To quantitatively measure quality of service, the following aspects are often considered: 

- Delay; 
- Jitter;
- Bandwidth;
- Packet Loss.

We focus the attention on the last parameter, measuring the quantity of packets discarded. The evaluation is carried on a simulator implemented in Python based on the Heap data structure. The idea is to reconstruct the ﬂow of the packets according to the features available from the trace, each packet is characterized by the snifﬁng time, the bit size and the DSCP marking. In this way we know the arriving time of the packet into the router with its size and priority marking. The array on which we work is composed by these information:

(Snifﬁng time, (Size, DSCP marking, Dscp decimal value))

This array is transformed into a binary heap, in particular Min Heap, with the command heapify. So, the router processes before the parent node and then the child node according to the position in the binary tree. Every time the router serves a packet, this one is popped out and then repushed into the binary structure with an updating time.

(FORMULA TIME UPDATE)

This is the main reason because we exploit the capacity of the binary tree to handle our priority queue composed by packets. In fact the idea is to serve always the root node of our MinHeap, and the complexity to ﬁnd it is O(1), so constant. Moreover when the root node is processed we replace it and restructure the Heap. The complexity for this operation is the previous complexity, for root extraction, in additionO(log2 n) (n = total number of nodes) to reassemble the hierarchical order of the nodes (packets). The last event is to push into the binary tree the new packet processed with the Time Updated always with the complexity of O(log2 n); every packet is released only in the last queue of the Router.[16] In the Figure 6 we show the environment developed by our code for the simulator architecture:

(foto aRCHITETTURA COSTRUITA)

The simulator environment is composed by two different blocks; the ﬁrst one for the classiﬁcation part (BA Classiﬁer), where the packets ﬂow arrives with as many queues as possible different service classes, and ﬁnally there is one last cumulative queue before the DoDeque part. In general, we have in the ﬁrst part a differentiation between queues based on the DSCP values, every packet is forwarded into its speciﬁc priority queue. This queue will have two attributes: the storage size (a percentage from the total amount of buffer size) and the speed of service, proportion to the class that it manages. For the ﬁrst feature we report our buffer size distribution between the macro service classes, which is used even for the subdivision in our classiﬁcation. We divide the total resource by this way:

|Service Class | Percentage of Buffer |
| ------------- | ------------- |
| Scavenger  |  15% |
| Best Effort | 40% |
| AF1  | 6% |
| AF2 | 6% |
| AF3 | 6% |
| AF4 | 6% |
| EF  | 16%  |
|Network & Internetwork Control | 5% |

For the second parameter, the service speed value of the queues is given a value equal to the queue buffer size divided by the TTL (Time To Live = 250ms). In the last queue of our simulator every packets is forwarded. The allocation of the resource is a central theme for the simulation, in our case we follow the considerations of [14]. The Buffer is dimensioned in this way:

(FORMULA Buffer Appenzeller)

In the Formula 4, C represents the output capacity of the Router, while 2TT is the Round Trip Time and at the denominator there is the squared root of n, where n is the total number of sessions. In our simulation we resize the router in the following way. the ﬁrst queues channel (InDequeue Part) is twice the dimension of the ﬁnal queue (DoDequeue Part) in order to obtain a more congested situation. In this way we test the ability of the network to discard packets following the Tail Drop algorithm in the beginning queues, while in the last queue applying a check on the priorities of the packets. In the simulation we consider two models for managing the resource allocation: MAM [9] and RDM [10]. The MAM (Maximum Allocation Model) does not allow the sharing of the unused resource so there is a deterministic allocation of the resource, while the RDM (Russian Dolls Model) allows sharing the resource between different service classes establishing a certain percentage of the resource that could be shared. 

### Results

Now we can observe the results for the MAM and RDM model. We train the model on the ﬁrst part of the trace, Thursday 7th March, 2019, with an amount of 2,501,286 packets. The test set is composed by the same amount of packets for each trace from Friday 8th March, 2019 to Thursday 14th March, 2019. We work on two different Heap binary tree, in the ﬁrst one we take into account snifﬁng time, dimension and marking based on the current DSCP while for the second structure we modify the DSCP marking using the our new classiﬁcation applying Random Forest. The results represent the Conﬁdence Interval at 95% for each possible capacity analyzed. This latter is the variable that changes in each singular simulation, the capacity ranges from 300 Mbps to 1 Gbps which are the average trafﬁc amount (considering the unidirectional ﬂow) and the maximum trafﬁc amount, with a step of 100 Mbps. In the simulation we consider the packets ﬂow divided between sessions. We extract the possible sessions applying the Hash Function SHA-256 to 4 different ﬁelds from each packet: Source IP address, Destination IP address, Source Port number and Destination Port number. By performing the hash transformation we are able to identify all the sessions in the part of communication that we analyze. A session is affected by congestion when it loses at least one packet, so our analysis focuses on the percentage of sessions affected by congestion during the simulation. Now we analyze the results, ﬁrstly in the MAM model and then with the RDM model. 

* MAM Model

(FOTO MAMA)

In the Figure 7 are reported the results according to the variation of the output capacity, which regulates the amount of available buffer size. In this speciﬁc case the classiﬁcation that we propose is not better than the current one until an output capacity of 900 Mbps. In fact, the current classiﬁcation is able to hit a lower percentage of sessions during the congestion. The worst results are obtained with the capacity from 300 Mbps to 500 Mbps where for the current classiﬁcation are hit from 30% to little bit more than the 10% while using our marking are hit more than the 50% of sessions and lower than 20%. Only in the last part we have a better results, where the output capacity is between 900 Mbps and 1 Gbps; here the conﬁdence interval goes between a little bit more than 10% of sessions hit and little less than 10%.

* RDM Model
In the RDM (Russian Dolls Model) simulation we establish the percentage of resource possible to share between different service classes. The idea is to check the amount of empty queue for each class and if the percentage of usage is less than a speciﬁc threshold we can use this queue for other classes. We decide to analyse three different sharing resource observing the queue at 20%, 50% and 80%. These three values are the thresholdlessthanwecansharetheresourcewithotherservice classes, always according to the hierarchy priority. So, the ﬁrst possible queue to be ﬁlled is the Scavenger queue until the Network and Internetwork Control queue. The ﬁrst analysis we present is with the threshold ﬁxed at the 20%, in the Figure 8 we have the results. Our proposed classiﬁcation is deﬁnitely better than the classiﬁcation currently used. In fact, only in the ﬁrst part of the analysis for a capacity that goes from 300 Mbps to 400 Mbps is better the current classiﬁcation, while from 500 Mbps until 1 Gbps the congestion affects a less percentage of sessions hit by the loss of at least one packet. It is interesting to make attention on the last three output capacity from 800 Mbps to 1 Gbps where our classiﬁcation allows to the router to hit surely less than the 10% of the total number of sessions. Whereas the current classiﬁcation has the upper bound of the conﬁdence interval more than the 10%. Now we can observe in the Figure 9 and the Figure 10 the behaviour of the router with 50% and 80% as checking threshold.

(FOTO RDM 20%)

Both the analysis with the 50% shared resource and the 80% has a similar trend for what it concerns the different output capacity and the consequent size of the buffer following [14]. In fact, with a capacity equal to 300 Mbps, 400 Mbps or 500 Mbps, the current classiﬁcation is better by affecting a lower percentage of ﬂows. However, we notice a difference between the plot with the threshold at 50% compared to the one with at 80% because the percentage of ﬂows affected by the second graph is greater than the ﬁrst one and in general the conﬁdence intervals cover values with higher percentages. Certainly the improvement that we have after the 500 Mbps is clear in both cases. Taking inspiration from the last reﬂection about the differences between the Figure 9 and Figure 10 we decide to compare the behaviour of the RDM model, marking the packets with our classiﬁcation, with respect to the three different threshold (20%, 50% and 80%). The Figure 11 sums up the behaviour in the three cases. It is clear how the router improves globally with our classiﬁcation, when it can forward the trafﬁc in the different queues of the services offered. However comparing the individual percentages of sharing there is a worsening as the available shared resource increases. In fact, we see how passing from 20% of shared resource to 50% we get worse in terms of conﬁdence intervals compared to the percentages of sessions affected by the loss of at least one packet. This trend gets worse by checking up to 80% of the resource used. Overall, we see that in all three cases we have an improvement with the increase in output capacity and the consequent growth in size of the buffer available. Our differentiation generally improves compared to the current classiﬁcation, but at the same time sharing too much resource increases the risk of service classes being clogged with packets from other services.

(foto RDM E COMPARISON)

### Conclusions

We can observe in which situation our proposed classiﬁcation is better than the current one and when not. We get our best result analysing the RDM model, allowing the sharing of resources between the different service queues. Certainly through the differentiation of the services proposed we improve the service offered when we can exploit the unused resource over time, allowing different services to beneﬁt from the unused resource. Completely the opposite is the result in the MAM model where sharing the resource is not allowed. In fact, by increasing the granularity within the macro-classes the current classication affects only the sessions related to the Best-Effort and Scavenger service instead using our proposed classiﬁcation we are also affecting the AF class, so probably much of the resource that we allocate to the remaining sub-classes is not used and surely this is an aspect that we need to improve. In the future we plan to propose an architecture that enables a dynamic QoS. Our proposal has increased the granularity of the service classes, but always in a static environment where the number of classes is ﬁxed. The real change, will be possible, when the routers could infer on the real-time request of the users analyzing the trafﬁc. It could deﬁne a temporal window, within which it evaluates whether the number of classes at time t-1 are still valid at time t; choosing between decrease or increase the available service classes. In this way the network will be able to predict the users future request by minimizing the number of sessions affected by packet loss. 


