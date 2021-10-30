from scapy.all import*

counter=0
for i in range(100):
     
     a=IP()
     a.dst="157.240.1.35" #facebook ip 
     a.ttl=i
     b=ICMP()
     p=a/b
     send(p)
     counter+=1
   
     
     if sr1(p).src == p.dst and counter >1 :
         print("The amount of routers that we have passed is :", i-1)
         break
   
    
