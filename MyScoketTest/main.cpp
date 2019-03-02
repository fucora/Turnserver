#include <cstdio> 
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h> 
#include<arpa/inet.h>>    
#include <netdb.h> 
#include "main.h"

int main()
{
    printf("hello from MyScoketTest!\n");
	StartUdpClient();
    return 0;
}

//*********************************************************************************
void StartUdpClient()
{
	int port = 8888;
	int sockfd;
	int i = 0;
	int z;
	char buf[80], str1[80];
	struct hostent *host;
	struct sockaddr_in adr_srvr;


	if ((host = gethostbyname("192.168.100.142")) == NULL) {
		herror("gethostbyname error!");
		exit(1);
	}

	adr_srvr.sin_family = AF_INET;
	adr_srvr.sin_port = htons(port);
	adr_srvr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(adr_srvr.sin_zero), 8);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket error!");
		exit(1);
	}

	printf("msg to server:\n");
	fgets(buf, sizeof(buf) - 1, stdin);

	printf("send ....\n");
	z = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&adr_srvr, sizeof(adr_srvr));
	if (z < 0) {
		perror("sendto error");
		exit(1);
	}


	sprintf(buf, "stop\n");
	z = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&adr_srvr, sizeof(adr_srvr));
	if (z < 0) {
		perror("sendto error");
		exit(1);
	}

	close(sockfd);
}