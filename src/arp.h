/* ========================================================================
   $HEADER FILE
   $File: arp.h $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Description: $
   $Revisions: $
   ======================================================================== */

#if !defined(ARP_H)
#define ARP_H

#include <pthread.h>
#include <stdint.h>

struct ArpPoison
{
    uint32_t SpoofIP;
    uint32_t TargetIP;
    char TargetMAC[6];
};

int ArpSetupSocket(uint32_t recv_timeout_ms);

int ArpResolveIP(const char *interface, uint32_t ip_address, char *mac_address);

int ArpSendRequest(const char *interface, uint32_t ip_address);
int ArpSendResponse(int sd, uint32_t spoof_ip_address, char *target_mac, uint32_t target_ip);

int ArpGetResponse(int sd, uint32_t *ip_address, char *mac);

pthread_t ArpStartPoisoning(const char *interface, ArpPoison *poisons, int poison_count);

#endif
