#include <pcap.h>
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

	pcap_t *pcap_desc;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_desc = pcap_open_offline(argv[1], errbuf);

	interfaces = pcap_lookupdev(errbuf);

	if (interfaces == NULL) {
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("Interfaces : %s\n", interfaces);


	pcap_loop(pcap_desc, 0, packetHandler, NULL);
	printf("end");
	return 0;
}

void packetHandler(u_char *udata, const struct pcap_pkthdr *pkt, const u_char *packet) {
	i++;
	const struct ether_header *ethp;
	const struct ip *iphd;
	const struct tcphdr *tcph;
	struct arphdr *arp_hdr;
	short ether_type;
	
	packet += sizeof(struct ether_header);
	iphd = (struct ip *)packet;
	
	ethp = (struct ether_header *)(packet += sizeof(struct ether_header));
	ether_type = ntohs(ethp->ether_type);
	
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
	
	printf("Src IP : %s\n", inet_ntoa(iphd->ip_src));
	printf("Dst IP : %s\n", inet_ntoa(iphd->ip_dst));
    printf("Src Port : %d\n" , ntohs(tcph->source));
    printf("Dst Port : %d\n" , ntohs(tcph->dest));
	printf("Protocol : ");
	if (ntohs(ethp->ether_type) == ETHERTYPE_IP) {
		printf("(IP)");
	} 
	if (iphd->ip_p == IPPROTO_TCP)
    {
		printf("(TCP Protocol)");
    }
	if (ether_type == ETHERTYPE_IPV6) {
		printf("(IPV6)");
	}
	if (ether_type == ETHERTYPE_ARP)
	{
		printf("(ARP)");
	}
	printf("\n");
	printf("============================================\n");
}