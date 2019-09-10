# Going Beyond DiffServ in IP Traffic Classification

As the number of Internet users continues to grow, network performance requirements must increase right along with them. In addition, many of the latest online services require highnetworkperformance.Theprimarygoalofqualityofservice is managing resources by setting priorities for speciﬁc types of data (video, audio, ﬁles). Actually packets are classiﬁed through DiffServ architecture based on the *RFC 4594* So, there are features which identify packets from a particular service class. In this paper, we propose a methodology able to detect these distinctive characteristics and improve the granularity of service classes. In fact, the idea is to establish the new number of services through a sub-classiﬁcation starting from the macro service classes. The evaluation between the two different classiﬁcation methods, the current one and the proposed one, takes place through a simulation testing the behaviour of the network during congestion; considering the percentage of ﬂows hit by packet loss. We validate the approach on the _MAWI_ data set. We analyze the model conditions which favor our classiﬁcation with respect to the current one and vice versa.

### Introduction

The capability to provide resource assurance and service differentiation in a network is referred to as Quality of Service (QoS). Resource assurance is critical for new applications to ﬂourish and prosper, moreover the Internet will become a truly multiservice network only improving service differentiation. One of the core building blocks for enabling QoS is represented by Differentiated Services (DiffServ). This architecture manages the problem related to resource allocation; packets get dropped or delayed because the resources in the network cannot meet all the trafﬁc demands. This service model was proposed to overcome the Integrated Services [2] architecture (IntServ), a ﬁrst attempt made by IETF to ensure QoS, based on per-ﬂow resource reservation. Flow-based algorithms have the ability to offer a good quality of service to one or more ﬂows because they reserve all the necessary resources along the way but this approach is not well suited for systems where thousands or millions of ﬂows circulate. In addition, routers maintain an internal state for each ﬂow, which makes them vulnerable to router failures. The IETF therefore turned to a simpler approach aimed at quality of service, which could be implemented mostly locally in each router, without involving the entire path. This system (DiffServ) is based on classes as opposed to IntServ based on ﬂows. The trafﬁc injected by the user into the network is mapped by the edge routers into the appropriate forwarding classes. The forwarding class is directly encoded into the packet header. This information is used by the interior nodes of the network to differentiate the treatment of the packets, because the forwarding classes may indicate drop priority or resource priority. In this paper, we propose a methodology able to improve the quality of service for what it concerns packets loss. Our idea is to propose a different classiﬁcation, starting from the current one, we want to increase the granularity of the macro service classes. For the evaluation, we use the MAWI dataset, containing daily trafﬁc traces of a transpaciﬁc backbonelink,weobservethebehaviourofthenetworkduring congestion in the MAM and RDM model, analysing which classiﬁcation obtains better results.

### DiffServ Architecture

DiffServ architecture was proposed by the IETF publishing RFC 2474 [3]. It relies on a mechanism to classify and mark packets as belonging to a speciﬁc class of service, using 8 bits for the Differentiated Services (DS) ﬁeld in the IP header. This ﬁeld is composed by two components, the 6 most signiﬁcant bits identify the DSCP (Differentiated Services Code Point) while the 2 least signiﬁcant bits deﬁne the ECN (Explicit Congestion Notiﬁcation). Classiﬁcation is based only on the DSCP ﬁeld, while the ECN ﬁeld is used for router communication in congestion detection. Each router is conﬁgured to differentiate trafﬁc based on its set of classes. Each trafﬁc class can be managed differently, ensuring preferential treatment for higher-priority trafﬁc. In DiffServ complex functions, such as packet classiﬁcation, can be carried out at the edge of the network by edge routers. Whereas core routers simply apply per-hop behaviour treatment (PHB) which deﬁnes the packet forwarding properties associated to a speciﬁc trafﬁc class. In theory, a network could have up to 64 different trafﬁc classes using the 64 available DSCP values, this gives to the network operator great ﬂexibility. In practice DiffServ recommend, but do not require, certain encodings. Most networks use the following commonly PHB:

• Default Forwarding (DF) 
• Expedited Forwarding (EF) 
• Assured Forwarding (AF) 
• Class Selector (CS)

*A. Default Forwarding*

Default Forwarding (DF) PHB is applied to any trafﬁc that does not meet the requirements of any other service classes. Typically, DF has best-effort forwarding characteristics. The recommended DSCP for DF is 0.[4]

*B. Expedited Forwarding* 

Expedited Forwarding (EF) PHB has the characteristics of low delay, low loss and low jitter. These characteristics are suitable for voice, video and other real-time services. EF trafﬁc is often given strict priority queuing above all other classes. The recommended DSCP for EF is 46. [6]

*C. Assured Forwarding* 

Assured Forwarding (AF) allows the operator to provide assurance of delivery as long as the trafﬁc does not exceed some preﬁxed rate. Trafﬁc that exceeds the rate faces a higher probability of being dropped if congestion occurs. The AF is composed by four separated classes where all have the same priority. Within each class, packets have a drop precedence (high, medium or low) where higher precedence means more probabilitytobedropped.Thecombinationofclassesanddrop precedence yields twelve separated DSCP encodings from AF11 to AF43. [5] [7]

*D. Class Selector*

Before the DiffServ architecture, IPv4 networks could use the IP precedence ﬁeld in the ToS [8] byte of the IPv4 header to mark priority trafﬁc. The IP precedence was not widely used, so the IETF agreed to reuse the ToS octet as the DS ﬁeld for DiffServ networks. In order to maintain backward compatibility with network devices that still use the IP Precedence ﬁeld, was deﬁned the Class Selector PHB. The Class Selector code points are of the binary form xxx000. The ﬁrst three bits are for the IP precedence bits. Each IP precedence value can be mapped into a DiffServ class. CS0 maps to IP precedence 0, CS1 to IP precedence 1, and so on. If a packet is received from a non-DiffServ-aware router, it can understand the encoding as a Class Selector code point.



<p align="center">
<img src="https://github.com/davidemedusaureli/ToS-in-TCP-IP/blob/master/diagramma.png" width="600">
 </p>

 Analyze packets from the Mawi_Group database traces to identify the main features in the ToS definition, or rather in the CF fields consisting of 6 bits for DSCP and 2 bits for ECN.
