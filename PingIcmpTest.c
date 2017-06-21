#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

int DEFAULT_TIMES = 4;
struct icmp {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short sequence;
	struct timeval timestamp;
};

struct ip {
#if __BYTE_ORDER == __LITTLE_ENDLAN
	unsigned char	hlen:4;
	unsigned char	version:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	version:4;
	unsigned char	hlen:4;
#endif
	unsigned char	tos;
	unsigned short	len;
	unsigned short	id;
	unsigned short	offset;
	unsigned char	ttl;
	unsigned char	protocol;
	unsigned short	checksum;
	struct in_addr	ipsrc;
	struct in_addr	ipdst;
};

unsigned short CheckSum(unsigned short *, int);
float timediff(struct timeval *, struct timeval *);
void pack(struct icmp *, int);
int unpack(char *, int, char *);

char buf[1024] = {0};

int main(int argc, char *argv[])
{
	struct hostent *host;
	struct icmp sendicmp;
	struct sockaddr_in to;
	struct sockaddr_in from;
	int sockfd;
	int ch;
	int i, n;
	int nsend = 0;
	int nreceived = 0;
	int fromlen = 0;
	in_addr_t inaddr;

	memset(&from, 0, sizeof(struct sockaddr_in));
	memset(&to, 0, sizeof(struct sockaddr_in));
	if (argc < 1){
		printf("Usage: ping destination [-c count]");
		return 1;
	}
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		printf("socket() error\n");
		exit(1);		
	}
	if (inaddr = inet_addr(argv[1]) == INADDR_NONE) {
		if ((host = gethostbyname(argv[1])) == NULL){
			printf("gethostbyname() error\n");
			exit(1);
		}
		to.sin_addr = *(struct in_addr *)host->h_addr_list[0];
	} else {
		to.sin_addr.s_addr = inaddr;
	}
	
	
	to.sin_family = AF_INET;
	printf("ping %s (%s) : %d bytes of data.\n", argv[1], inet_ntoa(to.sin_addr), (int)sizeof(struct icmp));
	for (i = 0; i < DEFAULT_TIMES; i++) {
		nsend++;
		memset(&sendicmp, 0, sizeof(struct icmp));
		pack(&sendicmp, nsend);
		if (sendto(sockfd, &sendicmp, sizeof(struct icmp), 0,  (struct sockaddr *)&to, sizeof(to)) == -1)
		{
			printf("sento() error\n");
			continue;
		}
		
		if ((n = recvfrom(sockfd, buf, 1024, 0, (struct sockaddr *)&from, &fromlen)) < 0)
		{
			printf("recvfrom() error\n");
			continue;
		}

		nreceived++;
		if (unpack(buf, n, inet_ntoa(from.sin_addr)) == -1) {
			printf("unpack() error\n");
		}
		sleep(1);

	}

	printf("------ %s ping statistics -----", argv[1]);
	printf("%d packets transmitted, %d received, %%%d packet loss", nsend, nreceived, (nsend - nreceived) / nsend * 100);
}

float timediff(struct timeval *begin, struct timeval *end)
{
	int n;
	n = (end->tv_sec - begin->tv_sec) * 1000000 + (end->tv_usec - begin->tv_usec);
	return (float)(n / 1000);
}

void pack(struct icmp *pkg, int sequence)
{
	pkg->type = 8;
	pkg->code = 0;
	pkg->id = getpid();
	pkg->sequence = sequence;
    gettimeofday(&(pkg->timestamp), 0);
	pkg->checksum = CheckSum((unsigned short *)pkg, sizeof(struct icmp));
}

unsigned short CheckSum(unsigned short *addr, int len)
{
	unsigned int sum = 0;
	while (len > 1) {
		sum += *addr++;
		len -=2;
	}

	if (len == 1) {
		sum += *(unsigned char *)addr;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short ) ~sum;
}

int unpack(char *buf, int len, char *addr)
{
	int i, ipheadlen;
	struct ip *ip;
	struct icmp *icmp;
	float rtt;
	struct timeval end;
	ip = (struct ip *)buf;
	ipheadlen = ip->hlen << 2;
	icmp = (struct icmp *)(buf + ipheadlen);
	len -= ipheadlen;

	if (len < 8) {
		printf("ICMP packets\'s length is less than 8\n");
		return -1;
	}

	if (icmp->type != 0 || icmp->id != getpid()) {
		printf("ICMP packets are not send by us\n");
		return -1;
	}
	gettimeofday(&end, 0);
	rtt = timediff(&icmp->timestamp, &end);
	printf("%d bytes from %s : icmp_seq=%u ttl=%d rtt=%fms \n",len, addr, icmp->sequence, ip->ttl, rtt);
}






















