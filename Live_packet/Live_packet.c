#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

void packetHandler(u_char *udata, const struct pcap_pkthdr *pkt, const u_char *packet);
	int i = 0;

int main(int argc, char **argv) {
	char *interfaces;
	char *network;
	char *mask;
	struct in_addr net_addr, mask_addr;
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	int ret;

	pcap_t *pcap_desc;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	interfaces = pcap_lookupdev(errbuf);
	ret = pcap_lookupnet(interfaces, &netp, &maskp, errbuf);
	printf("Interfaces : %s\n", interfaces);
	
	net_addr.s_addr = netp;
    	network = inet_ntoa(net_addr);
   	printf("Network : %s\n", network);
   	mask_addr.s_addr = maskp;
    	mask = inet_ntoa(mask_addr);
    	printf("Mask : %s\n", mask);
    
    	pcap_desc = pcap_open_live(interfaces, BUFSIZ, 0, -1, errbuf);

	pcap_loop(pcap_desc, 0, packetHandler, NULL);
	printf("end");
	return 0;
}

void packetHandler(u_char *udata, const struct pcap_pkthdr *pkt, const u_char *packet) {
	i++;
	
	short et_type;
	const struct ether_header *ethp;
	ethp = (struct ether_header *)packet;
	et_type = ntohs(ethp->ether_type);
	
	if (et_type == ETHERTYPE_IP) {
		struct ip *iphd = (struct ip*)(packet + sizeof(struct ether_header));
		printf("No.%d\n",i);
		printf("========Src MAC==============Dst MAC========\n");
		printf("== %02X:%02X:%02X:%02X:%02X:%02X "
  	      "-> %02X:%02X:%02X:%02X:%02X:%02X ==\n",
  	    ethp->ether_shost[0],
  	    ethp->ether_shost[1],
 	    ethp->ether_shost[2],
  	    ethp->ether_shost[3],
  	    ethp->ether_shost[4],
  	    ethp->ether_shost[5],
     
  	    ethp->ether_dhost[0],
  	    ethp->ether_dhost[1],
  	    ethp->ether_dhost[2],
 	    ethp->ether_dhost[3],
  	    ethp->ether_dhost[4],
 	    ethp->ether_dhost[5]
	     );
	     
		printf("(=== IP ===)\n");
		printf("Src IP : %s\n", inet_ntoa(iphd->ip_src));
		printf("Dst IP : %s\n", inet_ntoa(iphd->ip_dst));
		
		if (iphd->ip_p == IPPROTO_TCP) {
    		struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			printf("(TCP Protocol)\n");
			printf("Src Port : %d\n" , ntohs(tcph->source));
 			printf("Dst Port : %d\n" , ntohs(tcph->dest));
  		}
  		if (iphd->ip_p == IPPROTO_UDP) {
			printf("(UDP Protocol)\n");
			struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			printf("Src Port : %d\n" , ntohs(udph->source));
 			printf("Dst Port : %d\n" , ntohs(udph->dest));
  		}
  		
  	}
	if (et_type == ETHERTYPE_IPV6) {
		printf("(IPV6)");
	}
	if (et_type == ETHERTYPE_ARP) {
		printf("(ARP)");
	}
	if (et_type == ETHERTYPE_VLAN) {
		printf("(VLAN)");
	}
	if(et_type == ETHERTYPE_LOOPBACK) {
		printf("(LOOPBACK)");
	}
	printf("============================================\n");
}
