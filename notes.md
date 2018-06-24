currently not using dns type in dns queries as it is hard to match this type using snort rules(will need to check for bytes in the payload and these bytes are not always on a fixed position).
Pcap files are rewritten to the destination vm with the following command:
tcprewrite --infile=072a16f4c24332ec1dbbc8ea6df36087.pcap --outfile=072Local.pcap --dstipmap=127.0.0.1/16:192.168.2.137/32
attacks are replayed using the following command:
tcpreplay -i interface pcapfile

#Network setup
An attacker node is present on subnet 1. This node will use tcpreplay to replay an attack and will try to send it out to subnet 2.
The target node is present on subnet 2 and will be the target of the attack.
The attack pcap will be modified and the ip address of this node will be set as the target ip for the attack.
Snort has been set up as a bridge between these two subnets within my network.
Whenever Snort detects a packet on subnet 1 it will ignore the packet if it satisfied a rule, or forward the packet to subnet 2 if it does not.
Thus any traffic that matches one of the rules in the ruleset will never reach the target node.

Both snort and suricata are set up with 4GB of RAM memory and 2 cores of an intel L5630 CPU.



# DNS based attack 072a
snort rules for dns based attacks with just the following rule specification:
drop ip any 53 -> $HOME_NET any (msg:"DNS DDoS alert"; sid:1000002; classtype:denial-of-service;)
Have a detection rate of 100%
content field is not needed to gain a 100% detection rate, however this is needed to prevent legit dns requests from being dropped as well!!
content field does not decrease detection rate for dns based attack.

The DNS based attack contained a lot of unreassembled/malformed packets. Snort automatically discards these types of packets.
I will still need to do some research to check if this has any negative consequences for legitimate traffic.
93-94% of the packets in the dns based attack (072a...) were of this type and thus not even parsed by Snort.

Will still need to check if Snort forwards these packets to the other subnet.
regarding the discard problem:
http://seclists.org/snort/2017/q1/209

# base test

Determining base speed at which network starts dropping packets:
Using one rule for a different attack to test throughput.
Running attack at different speeds until network cannot handle it anymore.

using attack 151e for testing with the following rule in suricata:
drop UDP [83.27.228.55, 89.37.155.170, 79.47.163.85, 64.32.99.119, 2.183.220.133, 94.26.116.3, 156.212.74.194, 2.185.244.130, 89.235.78.139, 83.7.56.45, 196.210.218.106, 151.235.135.111] [10003] -> $HOME_NET [2687, 18292, 52518, 17094, 17274, 53866, 21561, 20988, 16237, 31171, 44074, 23414, 4976, 40184, 19865, 19949, 9765, 34520, 11361, 43970, 44039, 8529, 57225, 60176, 48233, 52575, 49703, 17281, 45912, 29357, 17678, 55508, 6180, 37959, 45349, 46273, 29415, 51772, 53171, 53930, 28365, 28281, 34461, 49039, 53507, 38424, 27755, 11942, 8535, 19377, 11161, 14236, 49068, 35660, 62989, 50234, 30877, 3025, 61861, 10805, 3067, 33791, 9358, 60206, 26168, 6348, 65453, 42399, 36016, 32509, 31031, 57591, 62209, 40173, 53688, 7404, 61227, 20123, 17245, 36494, 16087, 55352, 9304] (msg:"UDP DDoS alert"; classtype:denial-of-service;)

We measure the Cpu and memory usage.


failed on suricata

## snort
Measuring using attack 13c4 and the generated rule for this attack as well as random other rules:

## 1mbps test       1 rule          50 rules        250 rules   1000 rules      1000 rules with rule at bottom
Detection time:     0.35s           0.38s           0.37s       .37s            .34s
Packets sent:       16986           21502           23737       26749           25055 
Received by snort:  16986           21502           23737       26749           25055
Blocked by snort:   14112           17881           19729       22236           20831
Dropped by snort:   0               0               0           0               0
Received by target: 2874            3621            4008        4513            4224
Cpu usage:          12%             12%             12%         12%             12.5%
Mem usage:          4.3%            4.3%            4.3%        4.4%            4.4%

## 20mbps test
Detection time:     
Packets sent:       
Received by snort:  
Dropped by snort:   
Received by target:
Cpu usage:         
Mem usage:        

## 40mbps test
Detection time:     
Packets sent:       
Received by snort:  
Dropped by snort:   
Received by target: 
Cpu usage:          
Mem usage:          

## 60mbps test
Detection time:     
Packets sent:       
Received by snort:  
Dropped by snort:   
Received by target: 
Cpu usage:          
Mem usage:          

## 80mbps test
Detection time:     
Packets sent:       
Received by snort:  
Dropped by snort:   
Received by target: 
Cpu usage:          
Mem usage:          

## 100mbps test
Detection time:     
Packets sent:       
Received by snort:  
Dropped by snort:   
Received by target: 
Cpu usage:          
Mem usage:          

Apparently tcpreplay is not able to replay packets faster than 137Mbps.. tried different tweaks and that was the fastest speed I was able to reach with the average hovering around 100-110Mbps. Tried everything the FAQ said as well but nothing helped. http://tcpreplay.synfin.net/wiki/FAQ
Command that works best:
root@Attacker:~/DDosAttacks/targeted# tcpreplay --topspeed -i eth0 --preload-pcap --timer=nano --maxsleep=1 072aTarget.pcap

After doing some more research I realized that my hardware is what is limiting the replay speed. I however do not have hardware available that will achieve faster replay speed, thus I will have to make due with this hardware. All charts will be measured up to 125Mbps.

The ICMP based attacks are impossible to test. When we send 1Mbps using tcpreplay the attack is WAY larger for some reason. The other side receives 1.6M packets when we send 17k packets from the attacker.......







## Different attacks

# 072a DNS based attack
    This is a DNS based attack that contains a lot of unreassembled/malformed packets.
    Rule used:

# 13c4 UDP based attack
    This attack has a rule that needs to be tested
    Contains several bad udp length packets
    Rule used:

# 151e ICMP based attack
    Does not seem to contain malformed packets.
    This replay seems to cause a lot of problems.
    When sending 17k packets over 300k packets are received!
    Rule used:

# d27f UDP based attack
    All packets are longer than the protocol defines. Malformed might cause problems
    Rule used:

# e0b2 ICMP based attack
    Almost all packets are longer than protocol defines. Malformed might cause problems
    Rule used:

# e6ee DNS based attack
    All unreassembled packets cannot be parsed. This causes problems.
    Rule used:

# c606 TCP based attack
    
