/* ========================================================================
   $SOURCE FILE
   $File: scan.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Functions: $
static int ScanNetworkListener(void *args);
void ScanNetwork(const char *interface, const char *mask)

   $Description: This file contains all functions that have to do with scanning the network. $
   $Revisions: $
   ======================================================================== */

#include "scan.h"

#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arp.h"
#include "user_interface.h"

struct IPMACList
{
    uint32_t IPAddress;
    char MACAddress[6];
    IPMACList *Next;
};

struct ListenerInfo
{
    IPMACList *IpMacList;
    int Running;
};

static int ScanNetworkListener(void *args);

/* ========================================================================
   $ FUNCTION
   $ Name: ScanNetwork $
   $ Prototype: void ScanNetwork(const char *interface, const char *mask) $
   $ Params: 
   $    interface: The interface to use $
   $    mask: The network ip. ex: 192.168.0.0/24 $
   $ Description:  $
   ======================================================================== */
void ScanNetwork(const char *interface, const char *mask)
{
    uint32_t first, second, third, fourth, netmask_bits;

    if (sscanf(mask, "%d.%d.%d.%d/%d", &first, &second, &third, &fourth, &netmask_bits) != 5)
    {
        printf("The address must be in the form 192.168.0.0/24 or something similar\n");
        return;
    }

    if (first > 255 || second > 255 || third > 255 || fourth > 255 || netmask_bits > 32)
    {
        printf("The address must be in the form 192.168.0.0/24 or something similar\n");
        return;
    }

    uint32_t addr = (first << 24) | (second << 16) | (third << 8) | (fourth);

    // Convert the netmask number into the actual mask
    uint32_t netmask = 0xFFFFFFFF << (32 - netmask_bits);

    uint32_t start_addr = netmask & addr;
    uint32_t num_hosts = ~netmask;

    IPMACList *ipmaclist = (IPMACList*)malloc(sizeof(IPMACList));
    ipmaclist->Next = 0;

    ListenerInfo *info = (ListenerInfo*)malloc(sizeof(ListenerInfo));
    info->IpMacList = ipmaclist;
    info->Running = 1;

    IPMACList *cur_ipmac;

    // Start a listening thread
#define STACK_SIZE (16 * 1024)
    char *listener_memory = (char*)mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    pid_t child_id = clone(&ScanNetworkListener, listener_memory + STACK_SIZE, CLONE_VM | CLONE_FILES, info);

    printf("\n");
    for(uint32_t i = 0; i <= num_hosts; i++)
    {

        RenderProgressbar("Scanning Hosts", i / (float)num_hosts);

        // Send the arp request, then wait 10ms to not flood the network.
        if (ArpSendRequest(interface, i + start_addr) == -1)
        {
            return;
        }

        usleep(10000);
    }

    // Wait for child to finish executing before reading from list
    info->Running = 0;
    waitpid(child_id, 0, 0);

    printf("\nScan finished.\n\n");

    // Print out all found addresses:
    cur_ipmac = ipmaclist->Next;

    while (cur_ipmac)
    {
        printf("%d.%d.%d.%d <-> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
               (cur_ipmac->IPAddress >> 24) & 0xFF,
               (cur_ipmac->IPAddress >> 16) & 0xFF,
               (cur_ipmac->IPAddress >> 8) & 0xFF,
               (cur_ipmac->IPAddress >> 0) & 0xFF,
               cur_ipmac->MACAddress[0] & 0xFF,
               cur_ipmac->MACAddress[1] & 0xFF,
               cur_ipmac->MACAddress[2] & 0xFF,
               cur_ipmac->MACAddress[3] & 0xFF,
               cur_ipmac->MACAddress[4] & 0xFF,
               cur_ipmac->MACAddress[5] & 0xFF);

        cur_ipmac = cur_ipmac->Next;
    }
}

/* ========================================================================
   $ FUNCTION
   $ Name: int ScanNetworkListener $
   $ Prototype: static int ScanNetworkListener(void *args) $
   $ Params: 
   $    args: The IPMACList to populate with IP/MAC addresses $
   $ Description:  $
   ======================================================================== */
static int ScanNetworkListener(void *args)
{
    int sd;
    char mac_address[6];
    uint32_t ip_addr;
    ListenerInfo *info = (ListenerInfo*)args;
    IPMACList *cur_ipmac = info->IpMacList;

    sd = ArpSetupSocket(1000);
    if (sd == -1)
    {
        return -1;
    }

    while (info->Running)
    {
        if (ArpGetResponse(sd, &ip_addr, mac_address) == 0)
        {
            cur_ipmac->Next = (IPMACList*)malloc(sizeof(IPMACList));
            cur_ipmac = cur_ipmac->Next;
            cur_ipmac->IPAddress = ip_addr;
            memcpy(cur_ipmac->MACAddress, mac_address, 6);
            cur_ipmac->Next = 0;
        }
    }

    return 0;
}
