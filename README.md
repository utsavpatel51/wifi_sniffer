# wifi_sniffer(802.11 frame)

So this is a wifi sniffer that sniff your data or packet of layer 2,3,4

so in layer 2 we get frame control filed,3 address filed.
In frame control we get type & subtype of frame and all other filed

on layer 3 & 4 we get all data that actually wireshark are capable

To run this file you get pcap.h which is inbuilt in linux so to run on a linux you write gcc wifisniffer.c -lpcap which inculde 
the pcap.h file in your code
