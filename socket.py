import socket
from struct import unpack

s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)

while True:
packet = s.recvfrom(65565)
packet=packet[0]
ip_header=packet[0:20]
iph=unpack('!BBHHHBBH4s4s',ip_header)
version_ihl=iph[0]
version=version_ihl>>4
ihl=version_ihl & 0xF
iph_length=ihl*4
ttl=iph[5]
protocol=iph[6]
s_addr=socket.inet_ntoa(iph[8]);
d_addr=socket.inet_ntoa(iph[9]);
print("Version: "+str(version)+"IP header : "+str(iph_length))
tcp_header=packet[iph_length:iph_length+20]
tcph=unpack('!HHLLBBHHH',tcp_header)
source_port=tcph[0]
dest_port=tcph[1]
sequence=tcph[2]
acknowledgement=tcph[3]
doff_reserved=tcph[4]
tcph_length=doff_reserved>>4
print("Source Port: "+str(source_port)+"Dest Port: "+str(dest_port))
h_size=iph_length+tcph_length*4
data_size=len(packet)-h_size
data=packet[h_size:]
print('Data: ' +str(data))