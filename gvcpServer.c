/*
 *
 * Corence is pleased to support the open source community by making
 * GvcpServer available.
 *
 * Copyright (C) 2020 CORENCE AI SENSOR limited,a ningbo company.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

//#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#ifdef _WINDOWS_
#include <ws2tcpip.h>
#include <mswsock.h>
#include <malloc.h>
#include "winsock2.h"
#ifndef ETH_ALEN
#define ETH_ALEN       6              // 以太网地址大小
#define ETH_HLEN       14             // 以太网头部大小
#define ETH_DATA_LEN   1500           // 最大帧负载数据大小
#define ETH_FRAME_LEN  1514           // 最大帧大小，头部+负载数据
#endif
#else
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <net/route.h>
#endif
#include <errno.h>

//#include <iostream>

//using namespace std;
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

#define GVCP_DISCOVERY_CMD	2
#define GVCP_DISCOVERY_ACK	3
#define GVCP_FORCEIP_CMD	4
#define GVCP_FORCEIP_ACK	5
#define GVCP_READREG_CMD	0x80
#define GVCP_READREG_ACK	0x81
#define GVCP_WRITEREG_CMD	0x82
#define GVCP_WRITEREG_ACK	0x83
#define GVCP_READMEM_CMD	0x84
#define GVCP_READMEM_ACK	0x85

int SetIfAddr(char *ifname, char *Ipaddr, char *mask, char *gateway);
int GetIfAddr(char *ifname, char *Ipaddr, char *mask, char *gateway);
int addRoute(char *ipAddr, char *mask,char *gateWay,char* devName);

struct gvcp_cmd_header{
	uint8 cMsgKeyCode;//0x42
	uint8 cFlag;//0x11 allow broadcast ack;ack required
	uint16 wCmd;//discovery_cmd=2;FORCEIP_CMD = 4;READREG_CMD=0x80
	uint16 wLen;//payload length
	uint16 wReqID;// request id = 1;READREG id=12345
};

struct gvcp_forceip_payload{
	uint8 Mac[8];//last 6 byte
	uint8 CurIP[16];//last 4 byte
	uint8 SubMask[16];//last 4 byte
	uint8 Gateway[16];//last 4 byte
};

struct gvcp_ack_header{
	uint16 wStatus;//success=0;
	uint16 wAck;//discover_ack=3;forceip_ack=5;READREG_ACK=0x81
	uint16 wLen;
	uint16 wReqID;
};

struct gvcp_ack_payload{
	uint32 dwSpecVer;
	uint32 dwDevMode;
	uint8 Mac[8];//last 6 byte
	uint32 dwSupIpSet;
	uint32 dwCurIpSet;
	//uint8 unused1[12];
	uint8 CurIP[16];//last 4 byte
	uint8 SubMask[16];//last 4 byte
	uint8 Gateway[16];//last 4 byte
	char szFacName[32];//first
	char szModelName[32];//first
	char szDevVer[32];
	char szFacInfo[48];
	char szSerial[16];
	char szUserName[16];
};

struct gvcp_discover_cmd{
	struct gvcp_cmd_header header;
};
struct gvcp_discover_ack{
	struct gvcp_ack_header header;
	struct gvcp_ack_payload payload;
};
struct gvcp_forceip_cmd{
	struct gvcp_cmd_header header;
	struct gvcp_forceip_payload payload;
};
struct gvcp_forceip_ack{
	struct gvcp_ack_header header;
};
struct gvcp_readreg_cmd{
	struct gvcp_cmd_header header;
	uint32 dwRegAddr;
};
struct gvcp_readreg_ack{
	struct gvcp_ack_header header;
	uint32 dwRegValue;
};
struct gvcp_writereg_cmd {
	struct gvcp_cmd_header header;
	uint32 dwRegAddr;
	uint32 dwRegValue;
};

struct gvcp_writereg_ack {
	struct gvcp_ack_header header;
};

struct gvcp_readmem_cmd {
	struct gvcp_cmd_header header;
	uint32 dwMemAddr;
	uint32 dwMemCount;//last 2 byte
};
struct gvcp_readmem_ack {
	struct gvcp_ack_header header;
	uint32 dwMemAddr;
	char* pMemBuf;
};

#if 1//most hardware
#define MY_DEV_NAME "eth0"
#else
#define MY_DEV_NAME "ens33"
#endif
char m_szLocalIp[32]="192.168.101.57";
char m_szLocalMask[32]="255.255.255.0";
char m_szLocalGateway[32]="192.168.101.254";
char m_szLocalMac[32];
uint32 m_dwLocalPort;
uint8 m_LocalMacAddr[ETH_ALEN];
char m_szRemoteIp[32];
char m_szRemoteMask[32];
char m_szRemoteGateway[32];
char m_szRemoteMac[32];
uint32 m_dwRemotePort;
uint8 m_RemoteMacAddr[ETH_ALEN];
uint32 m_dwBroadcast = 0;

int gvcp_ack_discover(int iFd,char* szIp,char* szMask,char* szGateway, uint16 wReqID,uint32 dwPort,uint8* pMac)
{
    //char rgMessage[128] = "I am sending message to you!";
    //int iFd;
    int iSendbytes;
    int iOptval = 1;
    struct sockaddr_in Addr;
	int bNeedClose=0;
	if(iFd<0)
	{
		if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
		    printf("socket fail\n");
		    return -1;
		}
		bNeedClose=1;
	}
    if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
    {
        printf("setsockopt failed!");
    }
    memset(&Addr, 0, sizeof(struct sockaddr_in));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    Addr.sin_port = htons(dwPort);
	
	struct gvcp_discover_ack ack_msg;
	memset(&ack_msg, 0, sizeof(struct gvcp_discover_ack));
	ack_msg.header.wStatus=htons(0);
	ack_msg.header.wAck=htons(GVCP_DISCOVERY_ACK);
	ack_msg.header.wLen=htons(sizeof(struct gvcp_ack_payload));
	ack_msg.header.wReqID=htons(1);
	ack_msg.payload.dwSpecVer=htonl(0x010002);;
	ack_msg.payload.dwDevMode=htonl(1);
	//uint8 MyMac[6]={0xc4,0x2f,0x90,0xf1,0x71,0x3e};
	memcpy(&ack_msg.payload.Mac[2],m_LocalMacAddr,6);
	ack_msg.payload.dwSupIpSet=htonl(0x80000007);
	ack_msg.payload.dwCurIpSet=htonl(0x00005);
	//uint8 unused1[12];
	*((uint32*)&ack_msg.payload.CurIP[12])=inet_addr(m_szLocalIp);//last 4 byte
	*((uint32*)&ack_msg.payload.SubMask[12])=inet_addr(m_szLocalMask);//last 4 byte
	*((uint32*)&ack_msg.payload.Gateway[12])=inet_addr(m_szLocalGateway);//last 4 byte
	strcpy(ack_msg.payload.szFacName,"GEV");//first
	strcpy(ack_msg.payload.szModelName,"MV-AA003-50GM");//first
	strcpy(ack_msg.payload.szDevVer,"V2.8.6 180210 143913");
	strcpy(ack_msg.payload.szFacInfo,"GEV");
	strcpy(ack_msg.payload.szSerial,"00C31976084");
	strcpy(ack_msg.payload.szUserName,"");
	char* rgMessage=(char*)&ack_msg;
	uint32 dwMsgLen = sizeof(struct gvcp_discover_ack);
    //while (1)
    {
        if ((iSendbytes = sendto(iFd, rgMessage, dwMsgLen, 0, (struct sockaddr*)&Addr, sizeof(struct sockaddr))) == -1)
        {
            printf("sendto fail, errno=%d,%s\n", errno,strerror(errno));
            return -1;
        }
        printf("gvcp_ack_discover=%s, rgMessageLen=%d,iSendbytes=%d\n", rgMessage, dwMsgLen, iSendbytes);
        sleep(1);
    }
	if(bNeedClose>0)
	{
#ifdef _WINDOWS_
		closesocket(iFd);
#else
		close(iFd);
#endif
	}

    return 0;
}

int gvcp_cmd_discover(int iFd)
{
	//char rgMessage[128] = "I am sending message to you!";
	//int iFd;
	int iSendbytes;
	
	struct sockaddr_in Addr;
	int bNeedClose = 0;
	if (iFd < 0)
	{
		if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			printf("socket fail\n");
			return -1;
		}
		bNeedClose = 1;
	}
	int iOptval = 1;
#ifdef _WINDOWS_
	if (setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, (CHAR*)&iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt SO_REUSEADDR failed!");
	}
	BOOL	bBroadcast = true;
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST, (char*)&bBroadcast, sizeof(BOOL)) < 0)
	{
		printf("setsockopt SO_BROADCAST failed!");
	}
#else
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt failed!");
	}
#endif
	memset(&Addr, 0, sizeof(struct sockaddr_in));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
	Addr.sin_port = htons(3956);

	static struct gvcp_discover_cmd cmd_msg;
	memset(&cmd_msg, 0, sizeof(struct gvcp_discover_ack));
	cmd_msg.header.cMsgKeyCode = 0x42;
	cmd_msg.header.cFlag=0x11;//0x11 allow broadcast ack;ack required
	cmd_msg.header.wCmd= htons(GVCP_DISCOVERY_CMD);//discovery_cmd=2;FORCEIP_CMD = 4;READREG_CMD=0x80
	cmd_msg.header.wLen = htons(0);//payload length
	cmd_msg.header.wReqID = htons(1);// request id = 1;READREG id=12345

	char* rgMessage = (char*)&cmd_msg;
	uint32 dwMsgLen = sizeof(struct gvcp_discover_cmd);
	//while (1)
	{
		if ((iSendbytes = sendto(iFd, rgMessage, dwMsgLen, 0, (struct sockaddr*)&Addr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto fail, errno=%d,%s\n", errno, strerror(errno));
			return -1;
		}
		printf("gvcp_cmd_discover=%s, rgMessageLen=%d,iSendbytes=%d\n", rgMessage, dwMsgLen, iSendbytes);
		sleep(1);
	}
	if (bNeedClose > 0)
	{
#ifdef _WINDOWS_
		closesocket(iFd);
#else
		close(iFd);
#endif
	}

	return 0;
}
int gvcp_ask_readreg(int iFd, uint16 wReqID,uint32 dwPort, uint32 dwRegAddr, uint32 dwRegValue)
{
	//char rgMessage[128] = "I am sending message to you!";
	//int iFd;
	int iSendbytes;

	struct sockaddr_in Addr;
	int bNeedClose = 0;
	if (iFd < 0)
	{
		if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			printf("socket fail\n");
			return -1;
		}
		bNeedClose = 1;
	}
	int iOptval = 1;
#ifdef _WINDOWS_
	if (setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, (CHAR*)&iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt SO_REUSEADDR failed!");
	}
	BOOL	bBroadcast = true;
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST, (char*)&bBroadcast, sizeof(BOOL)) < 0)
	{
		printf("setsockopt SO_BROADCAST failed!");
	}
#else
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt failed!");
	}
#endif
	memset(&Addr, 0, sizeof(struct sockaddr_in));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
	Addr.sin_port = htons(dwPort);

	static struct gvcp_readreg_ack my_msg;
	memset(&my_msg, 0, sizeof(struct gvcp_readreg_ack));
	my_msg.header.wStatus = htons(0);
	my_msg.header.wAck = htons(GVCP_READREG_ACK);
	my_msg.header.wLen = htons(4);
	my_msg.header.wReqID = htons(wReqID);
	my_msg.dwRegValue = htonl(dwRegValue);;

	char* rgMessage = (char*)&my_msg;
	uint32 dwMsgLen = sizeof(struct gvcp_readreg_ack);
	//while (1)
	{
		if ((iSendbytes = sendto(iFd, rgMessage, dwMsgLen, 0, (struct sockaddr*)&Addr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto fail, errno=%d,%s\n", errno, strerror(errno));
			return -1;
		}
		printf("gvcp_ask_readreg=%s, rgMessageLen=%d,iSendbytes=%d\n", rgMessage, dwMsgLen, iSendbytes);
		sleep(1);
	}
	if (bNeedClose > 0)
	{
#ifdef _WINDOWS_
		closesocket(iFd);
#else
		close(iFd);
#endif
	}

	return 0;
}

int gvcp_ask_forceip(int iFd, uint16 wReqID, uint32 dwPort)
{
	//char rgMessage[128] = "I am sending message to you!";
	//int iFd;
	int iSendbytes;

	struct sockaddr_in Addr;
	int bNeedClose = 0;
	if (iFd < 0)
	{
		if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			printf("socket fail\n");
			return -1;
		}
		bNeedClose = 1;
	}
	int iOptval = 1;
#ifdef _WINDOWS_
	if (setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, (CHAR*)&iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt SO_REUSEADDR failed!");
	}
	BOOL	bBroadcast = true;
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST, (char*)&bBroadcast, sizeof(BOOL)) < 0)
	{
		printf("setsockopt SO_BROADCAST failed!");
	}
#else
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt failed!");
	}
#endif
	memset(&Addr, 0, sizeof(struct sockaddr_in));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
	Addr.sin_port = htons(dwPort);

	static struct gvcp_forceip_ack my_msg;
	memset(&my_msg, 0, sizeof(struct gvcp_forceip_ack));
	my_msg.header.wStatus = htons(0);
	my_msg.header.wAck = htons(GVCP_FORCEIP_ACK);
	my_msg.header.wLen = htons(0);
	my_msg.header.wReqID = htons(wReqID );

	char* rgMessage = (char*)&my_msg;
	uint32 dwMsgLen = sizeof(struct gvcp_forceip_ack);
	//while (1)
	{
		if ((iSendbytes = sendto(iFd, rgMessage, dwMsgLen, 0, (struct sockaddr*)&Addr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto fail, errno=%d,%s\n", errno, strerror(errno));
			return -1;
		}
		printf("gvcp_ask_forceip=%s, rgMessageLen=%d,iSendbytes=%d\n", rgMessage, dwMsgLen, iSendbytes);
		sleep(1);
	}
	if (bNeedClose > 0)
	{
#ifdef _WINDOWS_
		closesocket(iFd);
#else
		close(iFd);
#endif
	}

	return 0;
}

int gvcp_ask_writereg(int iFd, uint16 wReqID, uint32 dwPort)
{
	//char rgMessage[128] = "I am sending message to you!";
	//int iFd;
	int iSendbytes;

	struct sockaddr_in Addr;
	int bNeedClose = 0;
	if (iFd < 0)
	{
		if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			printf("socket fail\n");
			return -1;
		}
		bNeedClose = 1;
	}
	int iOptval = 1;
#ifdef _WINDOWS_
	if (setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, (CHAR*)&iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt SO_REUSEADDR failed!");
	}
	BOOL	bBroadcast = true;
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST, (char*)&bBroadcast, sizeof(BOOL)) < 0)
	{
		printf("setsockopt SO_BROADCAST failed!");
	}
#else
	if (setsockopt(iFd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
	{
		printf("setsockopt failed!");
	}
#endif
	memset(&Addr, 0, sizeof(struct sockaddr_in));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
	Addr.sin_port = htons(dwPort);

	static struct gvcp_writereg_ack my_msg;
	memset(&my_msg, 0, sizeof(struct gvcp_writereg_ack));
	my_msg.header.wStatus = htons(0);
	my_msg.header.wAck = htons(GVCP_WRITEREG_ACK);
	my_msg.header.wLen = htons(0);
	my_msg.header.wReqID = htons(wReqID);

	char* rgMessage = (char*)&my_msg;
	uint32 dwMsgLen = sizeof(struct gvcp_writereg_ack);
	//while (1)
	{
		if ((iSendbytes = sendto(iFd, rgMessage, dwMsgLen, 0, (struct sockaddr*)&Addr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto fail, errno=%d,%s\n", errno, strerror(errno));
			return -1;
		}
		printf("gvcp_ask_writereg=%s, rgMessageLen=%d,iSendbytes=%d\n", rgMessage, dwMsgLen, iSendbytes);
		sleep(1);
	}
	if (bNeedClose > 0)
	{
#ifdef _WINDOWS_
		closesocket(iFd);
#else
		close(iFd);
#endif
	}

	return 0;
}

int getLoaclMac(char *szMac) 
{
#if 1
    char *device=MY_DEV_NAME; //eth0是网卡设备名
    //unsigned char macaddr[ETH_ALEN]; //ETH_ALEN（6）是MAC地址长度
    struct ifreq req;
    int err,i;
    int s;
 
 
    s=socket(AF_INET,SOCK_DGRAM,0); //internet协议族的数据报类型套接口
    strcpy(req.ifr_name,device); //将设备名作为输入参数传入
    err=ioctl(s,SIOCGIFHWADDR,&req); //执行取MAC地址操作
    close(s);
    if(err != -1) { 
        memcpy(m_LocalMacAddr,req.ifr_hwaddr.sa_data,ETH_ALEN); //取输出的MAC地址
        for(i = 0; i < ETH_ALEN; i++) {
            sprintf(szMac, "%s%02x",szMac, m_LocalMacAddr[i]&0xff);
            if(i != ETH_ALEN - 1) {
                sprintf(szMac, "%s:", szMac);
            }
        }
 
    } else {
        return -1;
    }
#else
	bool ret = false;

	ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
	PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
	if (pAddresses == NULL)
		return false;
	// Make an initial call to GetAdaptersAddresses to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAddresses);
		pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
		if (pAddresses == NULL)
			return false;
	}


	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
	{
		// If successful, output some information from the data we received
		for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next)
		{
			// 确保MAC地址的长度为 00-00-00-00-00-00
			if (pCurrAddresses->PhysicalAddressLength != 6)
				continue;
			//char acMAC[32];
			memcpy(m_LocalMacAddr, pCurrAddresses->PhysicalAddress, ETH_ALEN); //取输出的MAC地址
			sprintf(szMac, "%02X:%02X:%02X:%02X:%02X:%02X",
				int(pCurrAddresses->PhysicalAddress[0]),
				int(pCurrAddresses->PhysicalAddress[1]),
				int(pCurrAddresses->PhysicalAddress[2]),
				int(pCurrAddresses->PhysicalAddress[3]),
				int(pCurrAddresses->PhysicalAddress[4]),
				int(pCurrAddresses->PhysicalAddress[5]));
			//macOUT = acMAC;
			ret = true;
			break;
		}
	}
	free(pAddresses);
#endif
    return 0;
}
#ifdef _WINDOWS_
extern void InitConsoleWindow();
int UdpServer(void) 
#else
int main(void) 
#endif
{
    int iRtn = GetIfAddr(MY_DEV_NAME, m_szLocalIp, m_szLocalMask, m_szLocalGateway);
	if(iRtn<0)
	{
		printf("GetIfAddr Error(%d) -> ResetIfAddr\n",iRtn);
		iRtn = SetIfAddr(MY_DEV_NAME, m_szLocalIp, m_szLocalMask, m_szLocalGateway);
		if(iRtn<0)
		{
			printf("SetIfAddr Error(%d)\n", iRtn);
		}
   		
	}
	iRtn = addRoute("255.255.255.0", "255.255.255.0", m_szLocalGateway, MY_DEV_NAME);
	if(iRtn<0)
	{
		printf("addRoute Error(%d)\n", iRtn);
	}
    int iAddrLength;
    char rgMessage[2014];
    int iOptval = 1;
    int iFd;
    struct sockaddr_in Addr;
 
    if ((iFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("socket fail\n");
        return -1;
    }
	else
	{
		printf("socket ok\n");
	}
    if (setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, &iOptval, sizeof(int)) < 0)
    {
        printf("setsockopt failed!\n");
    }
	else
	{
		printf("setsockopt ok\n");
	}
    memset(&Addr, 0, sizeof(struct sockaddr_in));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = INADDR_ANY;
    Addr.sin_port = htons(3956);
    iAddrLength = sizeof(Addr);

    if (bind(iFd, (struct sockaddr *)&Addr, sizeof(Addr)) == -1)
    {
        printf("bind failed!\n");
    }
	else
	{
		printf("bind ok\n");
	}
	
	int iTryCount = 10;
    while (1)
    {
		//gvcp_cmd_discover(iFd);
		//sleep(200);
		int iRecvLen=0;
		if ((iRecvLen=recvfrom(iFd, rgMessage, sizeof(rgMessage), 0, (struct sockaddr *)&Addr, &iAddrLength)) == -1)
		{
			printf("recv failed!\n");
		}
		printf("recv len =%d\n", iRecvLen);
		unsigned short* pBuf = (unsigned short*)rgMessage;
		strncpy(m_szRemoteIp, inet_ntoa(Addr.sin_addr), 16);
		strncpy(m_szRemoteMask, "255.255.255.0", 16);
		strncpy(m_szRemoteGateway, inet_ntoa(Addr.sin_addr), 16);
		m_dwRemotePort = ntohs(Addr.sin_port);
		getLoaclMac(m_szLocalMac);
		if (iRecvLen >= 8)
		{
			printf("recv from %s:%d-%04x-%04x-%04x-%04x\n",
				inet_ntoa(Addr.sin_addr), ntohs(Addr.sin_port),
				ntohs(pBuf[0]), ntohs(pBuf[1]), ntohs(pBuf[2]), ntohs(pBuf[3]));

			struct gvcp_cmd_header* pHeader = (struct gvcp_cmd_header*)rgMessage;
			static struct gvcp_cmd_header m_CmdHeader;
			m_CmdHeader.cMsgKeyCode = pHeader->cMsgKeyCode;// 0x42;
			m_CmdHeader.cFlag = pHeader->cFlag;//0x11 allow broadcast ack;ack required
			m_CmdHeader.wCmd = ntohs(pHeader->wCmd);//discovery_cmd=2;FORCEIP_CMD = 4;READREG_CMD=0x80
			m_CmdHeader.wLen = ntohs(pHeader->wLen);//payload length
			m_CmdHeader.wReqID = ntohs(pHeader->wReqID);// request id = 1;READREG id=12345
			if (m_CmdHeader.cMsgKeyCode == 0x42 && m_CmdHeader.wCmd == GVCP_DISCOVERY_CMD)
			{
				gvcp_ack_discover(iFd, m_szLocalIp, m_szLocalMask, m_szLocalGateway, m_CmdHeader.wReqID, m_dwLocalPort, m_LocalMacAddr);
			}
			else if (m_CmdHeader.cMsgKeyCode == 0x42 && m_CmdHeader.wCmd == GVCP_FORCEIP_CMD&&iRecvLen>=sizeof(struct gvcp_forceip_cmd))
			{
				struct sockaddr_in GetAddr;
				memset(&GetAddr, 0, sizeof(struct sockaddr_in));
				GetAddr.sin_family = AF_INET;
				GetAddr.sin_addr.s_addr = INADDR_ANY;
				GetAddr.sin_port = htons(3956);

				struct gvcp_forceip_cmd* pMyCmd = (struct gvcp_forceip_cmd*)rgMessage;

				uint8 GetMac[6];// = { 0xc4,0x2f,0x90,0xf1,0x71,0x3e };
				memcpy(GetMac, &(pMyCmd->payload.Mac[2]), 6);
				printf("maccmp %s:%02x:%02x:%02x:%02x:%02x:%02x\n",m_szLocalMac,
				GetMac[0],GetMac[1],GetMac[2],GetMac[3],GetMac[4],GetMac[5]);
				if (memcmp(m_LocalMacAddr, GetMac, 6) == 0)//匹配成功
				{
					
					GetAddr.sin_addr.s_addr = *((uint32*)&pMyCmd->payload.CurIP[12]);// = inet_addr("192.168.101.57");//last 4 byte
					strncpy(m_szLocalIp, inet_ntoa(Addr.sin_addr), 16);
					GetAddr.sin_addr.s_addr = *((uint32*)&pMyCmd->payload.SubMask[12]);// = inet_addr("255.255.255.0");//last 4 byte
					strncpy(m_szLocalMask, "255.255.255.0", 16);
					GetAddr.sin_addr.s_addr = *((uint32*)&pMyCmd->payload.Gateway[12]);// = inet_addr("192.168.101.254");//last 4 byte
					strncpy(m_szLocalGateway, inet_ntoa(Addr.sin_addr), 16);
					if(SetIfAddr(MY_DEV_NAME, m_szLocalIp, m_szLocalMask, m_szLocalGateway)<0)
						printf("SetIfAddr Failed"); 
					//reget if addr
					GetIfAddr(MY_DEV_NAME, m_szLocalIp, m_szLocalMask, m_szLocalGateway);
					//struct gvcp_forceip_payload
					gvcp_ask_forceip(iFd, m_CmdHeader.wReqID, m_dwRemotePort);
				}

			}
			else if (m_CmdHeader.cMsgKeyCode == 0x42 && m_CmdHeader.wCmd == GVCP_READREG_CMD&&iRecvLen >= sizeof(struct gvcp_readreg_cmd))
			{
				struct gvcp_readreg_cmd* pMyCmd = (struct gvcp_readreg_cmd*)rgMessage;

				uint32 dwRegAddr = ntohl(pMyCmd->dwRegAddr);
				uint32 dwRegValue = 0;
				if (dwRegAddr == 0x0014)//Current IP Configuration
				{
					//DHCP bit1
					//LLA bit2
					dwRegValue = 0x04;
				}
				else if (dwRegAddr == 0x00934)//(Gvcp Capability)
				{
					dwRegValue = 0xf8400007;//
				}
				else if (dwRegAddr == 0x00938)//heartbeat timeout
				{
					dwRegValue = 3000;//ms
				}
				else if (dwRegAddr == 0x00a00)//CCP (Control Channel Privilege)
				{
					dwRegValue = 0;
				}
				printf("readreg:%08x=%08x\n",dwRegAddr,dwRegValue); 
				gvcp_ask_readreg(iFd, m_CmdHeader.wReqID, m_dwRemotePort, dwRegAddr, dwRegValue);
			}
			else if (m_CmdHeader.cMsgKeyCode == 0x42 && m_CmdHeader.wCmd == GVCP_WRITEREG_CMD&&iRecvLen >= sizeof(struct gvcp_writereg_cmd))
			{
				struct gvcp_writereg_cmd* pMyCmd = (struct gvcp_writereg_cmd*)rgMessage;

				uint32 dwRegAddr = ntohl(pMyCmd->dwRegAddr);
				uint32 dwRegValue = ntohl(pMyCmd->dwRegValue);
				if (dwRegAddr == 0x0014)//Current IP Configuration
				{
					//DHCP bit1
					//LLA bit2
					//dwRegValue = 0x04;
					if(dwRegValue&0x02)
						printf("Set DHCP Enable\n"); 
					if(dwRegValue&0x04)
						printf("Set LLA Enable\n"); 
				}
				else if (dwRegAddr == 0x00934)//(Gvcp Capability)
				{
					//dwRegValue = 0xf8400007;//
					printf("Set Gvcp Capability:%08x\n",dwRegValue); 
				}
				else if (dwRegAddr == 0x00938)//heartbeat timeout
				{
					//dwRegValue = 3000;//ms
					printf("Set heartbeat timeout:%d\n",dwRegValue); 
				}
				else if (dwRegAddr == 0x00a00)//CCP (Control Channel Privilege)
				{
					//dwRegValue = 0;
					printf("Set CCP:%08x\n",dwRegValue); 
				}
				gvcp_ask_writereg(iFd, m_CmdHeader.wReqID, m_dwRemotePort);
			}
		}
    }

#ifdef _WINDOWS_
	closesocket(iFd);
#else
	close(iFd);
#endif

    return 0;
}


int SetIfAddr(char *ifname, char *Ipaddr, char *mask, char *gateway)
{
	int fd=0;
	int rc=0;
#ifdef _WINDOWS_

#else
	struct ifreq ifr;
	struct sockaddr_in *sin;
	struct rtentry  rt;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket   error");
		close(fd);
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	sin->sin_family = AF_INET;

	//ipaddr
	if (inet_aton(Ipaddr, &(sin->sin_addr)) < 0)
	{
		perror("inet_aton ipaddr error");
		close(fd);
		return -2;
	}
	uint32 dwLocalIp = sin->sin_addr.s_addr;
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
	{
		perror("ioctl   SIOCSIFADDR   error");
		close(fd);
		return -3;
	}

	//netmask
	if (inet_aton(mask, &(sin->sin_addr)) < 0)
	{
		perror("inet_pton netmask error");
		close(fd);
		return -4;
	}
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
	{
		perror("ioctl");
		close(fd);
		return -5;
	}
	//boardcast
	sin->sin_addr.s_addr = (dwLocalIp&0x00FFFFFF)|0xFF000000;
	//if (inet_aton(gateway, &(sin->sin_addr)) < 0)
	//{
	//	perror("inet_pton boardcast error");
	//	close(fd);
	//	return -8;
	//}
	if (ioctl(fd, SIOCSIFBRDADDR, &ifr) < 0)
	{
		perror("ioctl");
		close(fd);
		return -9;
	}
	//gateway
	memset(&rt, 0, sizeof(struct rtentry));
	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	if (inet_aton(gateway, &sin->sin_addr) < 0)
	{
		printf("inet_aton gateway error\n");
		return -6;
	}
	memcpy(&rt.rt_gateway, sin, sizeof(struct sockaddr_in));
	((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
	((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
	rt.rt_flags = RTF_GATEWAY;
	if (ioctl(fd, SIOCADDRT, &rt) < 0)
	{
		perror("ioctl(SIOCADDRT) error in set_default_route\n");
		close(fd);
		return -7;
	}
	close(fd);
#endif
	return 0;

}


int GetIfAddr(char *ifname, char *Ipaddr, char *mask, char *gateway)
{

	int fd;
	int rc;
	int ret;
	int i=0;
#ifndef _WINDOWS_
	struct ifreq ifr;
	struct sockaddr_in sin;
	struct sockaddr_in* p_sin=0;
	struct rtentry  rt;

	fd = socket(AF_INET, SOCK_DGRAM, 0);//internet协议族的数据报类型套接口
	if (fd < 0)
	{
		perror("socket   error");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);//将设备名作为输入参数传入
	p_sin = (struct sockaddr_in*)&ifr.ifr_addr;
	p_sin->sin_family = AF_INET;

	ret = ioctl(fd, SIOCGIFHWADDR, &ifr); //执行取MAC地址操作									
	if (ret < 0)
	{
		close(fd);
		perror("ioctl   SIOCGIFHWADDR   error");
		return -2;
	}
	
	{
		memcpy(m_LocalMacAddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN); //取输出的MAC地址
		for (i = 0; i < ETH_ALEN; i++) {
			sprintf(m_szLocalMac, "%s%02x", m_szLocalMac, m_LocalMacAddr[i] & 0xff);
			if (i != ETH_ALEN - 1) {
				sprintf(m_szLocalMac, "%s:", m_szLocalMac);
			}
		}
		printf("MacAddr is :%s\n", m_szLocalMac);
	}

	//get the broadcast addr
	/* 获取当前网卡的广播地址 */
	if (ioctl(fd, SIOCGIFBRDADDR, &ifr) < 0)
	{
		close(fd);
		return -3;
	}
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	m_dwBroadcast = sin.sin_addr.s_addr;
	printf("broadcast is :%s\n", inet_ntoa(sin.sin_addr));

	//get the ip addr
	/* 获取当前网卡的IP地址 */
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
	{
		close(fd);
		return -4;
	}
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	uint32 dwLocalIp = sin.sin_addr.s_addr;
	sprintf(m_szLocalIp,"%s", inet_ntoa(sin.sin_addr));
	printf("LocalIp is :%s(%x)\n", inet_ntoa(sin.sin_addr),dwLocalIp);

	/* 获取当前网卡的子网掩码 */
	if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0)
	{
		close(fd);
		return -5;
	}
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	sprintf(m_szLocalMask, "%s", inet_ntoa(sin.sin_addr));
	printf("LocalMask is :%s\n", inet_ntoa(sin.sin_addr));

	/* 获取当前网卡的gateway */
	//if (ioctl(fd, SIOCGADDRT, &ifr) < 0)
	//{
	//	close(fd);
	//	return -5;
	//}
	//memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	sin.sin_addr.s_addr = (dwLocalIp&0x00FFFFFF)|0xFE000000;
	sprintf(m_szLocalGateway, "%s", inet_ntoa(sin.sin_addr));
	printf("LocalGateway is :%s\n", inet_ntoa(sin.sin_addr));

	close(fd);
#else

#endif
	return 0;
}

int addRoute(char *ipAddr, char *mask,char *gateWay,char* devName)
{
  int fd;
  int rc = 0;
  struct sockaddr_in _sin;
  struct sockaddr_in *sin = &_sin;
  struct rtentry  rt;
 
  do
  {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
      printf("addRoute: socket   error\n");
      rc = -1;
      break;
    }
    //网关  
    memset(&rt, 0, sizeof(struct rtentry));
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateWay, &sin->sin_addr)<0)
    {
      printf( "addRoute:  gateWay inet_aton error\n" );
      rc = -2;
      break;
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    if(inet_aton(ipAddr, &((struct sockaddr_in *)&rt.rt_dst)->sin_addr)<0)
    {
      printf( "addRoute:  dst inet_aton error\n" );
      rc = -3;
      break;
    }
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    if(inet_aton(mask, &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr)<0)
    {
      printf( "addRoute:  mask inet_aton error\n" );
      rc = -4;
      break;
    }
 
    if(devName)
      rt.rt_dev = devName;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(fd, SIOCADDRT, &rt)<0)
    {
      printf( "ioctl(SIOCADDRT) error in set_route\n");
      rc = -5;
    }
  }while(0);
 
  close(fd);
  return rc;
}

