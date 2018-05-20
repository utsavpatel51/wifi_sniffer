#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void print_header_of_802(const u_char *, int);
void PrintData (const u_char * , int);
void print_subtype(int,int,const u_char *);
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
#define MAXBYTES2CAPTURE 65535

#ifdef WORDS_BIGENDIAN
typedef struct frame_control
{
    unsigned int subtype:4; 
    unsigned int protoVer:2;
    unsigned int version:2;

    unsigned int order:1;  
    unsigned int protected:1;
    unsigned int moreDate:1;
    unsigned int power_management:1;

    unsigned int retry:1; 
    unsigned int moreFrag:1;
    unsigned int fromDS:1;
    unsigned int toDS:1;
}frame_control;

struct ieee80211_radiotap_header{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
    u_int64_t MAC_timestamp;
    u_int8_t flags;
    u_int8_t dataRate;
    u_int16_t channelfrequency;
    u_int16_t channFreq_pad;
    u_int16_t channelType;
    u_int16_t channType_pad;
    u_int8_t ssiSignal;
    u_int8_t ssiNoise;
    u_int8_t antenna;
};

#else
typedef struct frame_control
{
    unsigned int protoVer:2;
    unsigned int type:2;
    unsigned int subtype:4;

    unsigned int toDS:1; 
    unsigned int fromDS:1;
    unsigned int moreFrag:1; 
    unsigned int retry:1; 

    unsigned int powMgt:1;
    unsigned int moreDate:1; 
    unsigned int protectedData:1; 
    unsigned int order:1; 
}frame_control;

struct ieee80211_radiotap_header{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
    u_int64_t MAC_timestamp;
    u_int8_t flags;
    u_int8_t dataRate;
    u_int16_t channelfrequency;
    u_int16_t channelType;
    int ssiSignal:8;
    int ssiNoise:8;
};
#endif
struct wi_frame {
    u_int16_t fc;
    u_int16_t wi_duration;
    u_int8_t da[6];
    u_int8_t sa[6];
    u_int8_t bssid[6];
    u_int16_t wi_sequenceControl;
    // u_int8_t wi_add4[6];
    //unsigned int qosControl:2;
    //unsigned int frameBody[23124];
};
struct ctrl_rts_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	ta[6];
	u_int8_t	fcs[4];
};
#define CTRL_RTS_LEN	(2+2+6+6+4)
struct ctrl_cts_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	fcs[4];
};

#define CTRL_CTS_LEN	(2+2+6+4)
int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
    printf("Finding available devices ... ");
    if(pcap_findalldevs(&alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create file.");
    }
    pcap_loop(handle , -1 , process_packet , NULL);
     
    return 0;   
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol)
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void print_header_of_802(const u_char *Buffer, int Size)
{
    struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)Buffer;    		
    fprintf(logfile , "\n");
    fprintf(logfile , "\n\n***********************802.11 Header*************************\n");  
    struct wi_frame *fr= (struct wi_frame *)(Buffer + rh->it_len);
    u_char *ptr;
    struct frame_control *fc=(struct frame_control*)(Buffer+rh->it_len);
    fprintf(logfile ,"type: %d",(unsigned int)fc->type);
    if(fc->type==0)
	fprintf(logfile ," (Management)\n");
    else if(fc->type==1)
	fprintf(logfile," (Control)\n");
    else if(fc->type==2)
	fprintf(logfile," (Data)\n");
    else
	fprintf(logfile," (Reserved)\n");
    fprintf(logfile ,"sub type: %d",(unsigned int)fc->subtype);
    print_subtype(fc->type,fc->subtype,Buffer);
    
}
void print_ethernet_header(const u_char *Buffer, int Size)
{
    print_header_of_802(Buffer,Size);
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-f Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
         
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                         
    fprintf(logfile , "\n###########################################################");
}
 
void print_udp_packet(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
     
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size);
    fprintf(logfile , "\n###########################################################");
}
 
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile , "\n");
         
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(logfile , "\n");
 
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(logfile , "\n###########################################################");
}
 
void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)  
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   ");
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
	
    }
}
void print_subtype(int type,int subtype,const u_char *Buffer){
struct ctrl_rts_t *rts=(struct ctrl_rts_t *)Buffer;
struct ctrl_cts_t *cts=(struct ctrl_cts_t *)Buffer;
if(type==0 && subtype==0)
	fprintf(logfile," (Association Request)");
else if(type==0 && subtype==1)
	fprintf(logfile," (Association Response)");
else if(type==0 && subtype==2)
	fprintf(logfile," (ReAssociation Request)");
else if(type==0 && subtype==3)
	fprintf(logfile," (ReAssociation Response)");
else if(type==0 && subtype==4)
	fprintf(logfile," (Probe Request)");
else if(type==0 && subtype==5)
	fprintf(logfile," (Probe Response)");
else if(type==0 && subtype==8)
	fprintf(logfile," (Beacon)");
else if(type==0 && subtype==9)
	fprintf(logfile," (ATIM)");
else if(type==0 && subtype==10)
	fprintf(logfile," (Disassociation)");
else if(type==0 && subtype==11)
	fprintf(logfile," (Authentication)");
else if(type==0 && subtype==12)
	fprintf(logfile," (Deauthentication)");
else if(type==0 && subtype==13)
	fprintf(logfile," (Action)");
else if(type==0 && (subtype==6 || subtype==7 || subtype==14 || subtype==15))
	fprintf(logfile,"Reserved");
if(type==1 && subtype==8)
	fprintf(logfile," (Block Ack Request)");
else if(type==1 && subtype==9)
	fprintf(logfile," (Block Ack)");
else if(type==1 && subtype==10)
	fprintf(logfile," (PS-Poll)");
else if(type==1 && subtype==11){
	fprintf(logfile," (RTS)\n");
	fprintf(logfile,"*************************RTS frame*****************\n");
	fprintf(logfile,"   |-Frame Control: %d\n",(unsigned int)rts->fc);
	fprintf(logfile,"   |-Duration: %d\n",(unsigned int)rts->duration);
	fprintf(logfile,"   |-Receiver Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", rts->ra[0] , rts->ra[1] , rts->ra[2] , rts->ra[3] , rts->ra[4] ,rts->ra[5]);
	fprintf(logfile,"   |-Transmitter adress: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", rts->ta[0] , rts->ta[1] , rts->ta[2] , rts->ta[3] , rts->ta[4] ,rts->ta[5]);	
	}
else if(type==1 && subtype==12){
	fprintf(logfile," (CTS)\n");
	fprintf(logfile,"*************************CTS frame*****************\n");
	fprintf(logfile,"   |-Frame Control: %d\n",(unsigned int)cts->fc);
	fprintf(logfile,"   |-Duration: %d\n",(unsigned int)cts->duration);
	fprintf(logfile,"   |-Receiver Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", cts->ra[0] , cts->ra[1] , cts->ra[2] , cts->ra[3] , cts->ra[4] ,cts->ra[5]);
	}
else if(type==1 && subtype==13)
	fprintf(logfile," (ACK)");
else if(type==1 && subtype==14)
	fprintf(logfile," (CF-end)");
else if(type==1 && subtype==15)
	fprintf(logfile," (CF-end + CF-ack)");
else if(type==1 && (subtype==0 ||subtype==1 ||subtype==2 ||subtype==3 ||subtype==4 ||subtype==5 ||subtype==6 ||subtype==7))
	fprintf(logfile," (Reserved)");
fprintf(logfile,"\n");
}
