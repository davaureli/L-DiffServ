# Going Beyond DiffServ in IP Traffic Classification

As the number of Internet users continues to grow, network performance requirements must increase right along with them. In addition, many of the latest online services require highnetworkperformance.Theprimarygoalofqualityofservice is managing resources by setting priorities for speciﬁc types of data (video, audio, ﬁles). Actually packets are classiﬁed through DiffServ architecture based on the *RFC 4594* So, there are features which identify packets from a particular service class. In this paper, we propose a methodology able to detect these distinctive characteristics and improve the granularity of service classes. In fact, the idea is to establish the new number of services through a sub-classiﬁcation starting from the macro service classes. The evaluation between the two different classiﬁcation methods, the current one and the proposed one, takes place through a simulation testing the behaviour of the network during congestion; considering the percentage of ﬂows hit by packet loss. We validate the approach on the _MAWI_ data set. We analyze the model conditions which favor our classiﬁcation with respect to the current one and vice versa. 

<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/diagramma.png" width="600">
 </p>

 Analyze packets from the Mawi_Group database traces to identify the main features in the ToS definition, or rather in the CF fields consisting of 6 bits for DSCP and 2 bits for ECN.
