/* ========================================================================
   $SOURCE FILE
   $File: interface.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Functions: $
void ListInterfaces()
int GetFirstInterface(char **interface)

   $Description: This file contains all functions that have to do with network interfaces. $
   $Revisions: $
   ======================================================================== */

#include <net/if.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
   $ FUNCTION
   $ Name: ListInterfaces $
   $ Prototype: void ListInterfaces() $
   $ Params: $
   $ Description: This function ouputs all interfaces to STDOUT $
   ======================================================================== */
void ListInterfaces()
{
    struct ifaddrs *addr_list, *cur_addr;

    getifaddrs(&addr_list);
    cur_addr = addr_list;

    printf("Interfaces:\n");

    while (cur_addr)
    {
        if (cur_addr->ifa_addr && (cur_addr->ifa_addr->sa_family == AF_PACKET) && (cur_addr->ifa_flags & IFF_LOOPBACK) == 0)
        {
            printf("\t%s\n", cur_addr->ifa_name);
        }

        cur_addr = cur_addr->ifa_next;
    }

    freeifaddrs(addr_list);
}

/* ========================================================================
   $ FUNCTION
   $ Name: GetFirstInterface $
   $ Prototype: int GetFirstInterface(char **interface) $
   $ Params: 
   $    interface: The location to put the first interface found. $
   $ Description: This function returns the first interface found $
   ======================================================================== */
int GetFirstInterface(char **interface)
{
    int if_count = 0;
    int iface_len;
    struct ifaddrs *addr_list, *cur_addr;

    getifaddrs(&addr_list);
    cur_addr = addr_list;

    *interface = 0;

    while (cur_addr)
    {
        if (cur_addr->ifa_addr && (cur_addr->ifa_addr->sa_family == AF_PACKET) && (cur_addr->ifa_flags & IFF_LOOPBACK) == 0)
        {
            if (*interface == 0)
            {
                iface_len = strlen(cur_addr->ifa_name);

                *interface = (char*)malloc(iface_len + 1);
                memcpy(*interface, cur_addr->ifa_name, iface_len);

                (*interface)[iface_len] = 0;
            }
            if_count++;
        }

        cur_addr = cur_addr->ifa_next;
    }

    freeifaddrs(addr_list);

    return if_count;
}
