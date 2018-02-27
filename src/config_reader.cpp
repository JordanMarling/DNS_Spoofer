/* ========================================================================
   $SOURCE FILE
   $File: config_reader.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/28 $
   $Functions: $
int ConfigRead(const char *filename, DNSConfig *config)

   $Description: This file contains all functions to do with reading the config file. $
   $Revisions: $
   ======================================================================== */

#include "config_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

/* ========================================================================
   $ FUNCTION
   $ Name: ConfigRead $
   $ Prototype: int ConfigRead(const char *filename, DNSConfig *config) $
   $ Params: 
   $    filename: The name of the config file to read $
   $    config: The DNSConfig struct to populate $
   $ Description: This function reads the config file and puts it into a DNSConfig struct. $
   ======================================================================== */
int ConfigRead(const char *filename, DNSConfig *config)
{

    // File
    FILE *fp;
    char *line = 0;
    size_t linesize = 0;
    ssize_t read;

    // DNS
    char url[128];
    char spoof_ip[16];
    DNSSpoof *cur_dns = 0;

    if ((fp = fopen(filename, "r")) == 0)
    {
        printf("Error opening config file: %s\n", filename);
        return -1;
    }

    // Initialize DNSConfig
    config->num_spoofs = 0;
    config->SpoofList = 0;

    while ((read = getline(&line, &linesize, fp)) != -1)
    {
        if (sscanf(line, "%s %s", url, spoof_ip) == 2)
        {
            DNSSpoof *tmp = (DNSSpoof*)malloc(sizeof(DNSSpoof));
            tmp->Next = 0;

            tmp->web_addr_len = strlen(url);
            tmp->web_address = (char*)malloc(tmp->web_addr_len + 1);
            memcpy(tmp->web_address, url, tmp->web_addr_len);
            tmp->web_address[tmp->web_addr_len] = 0;

            int first, second, third, fourth;
            if (sscanf(spoof_ip, "%d.%d.%d.%d", &first, &second, &third, &fourth) != 4)
            {
                printf("Invalid spoofing address.\n");
                return -1;
            }

            tmp->ip_address = (first << 24) | (second << 16) | (third << 8) | (fourth);

            if (cur_dns == 0)
            {
                config->SpoofList = tmp;
                cur_dns = tmp;
            }
            else
            {
                cur_dns->Next = tmp;
                cur_dns = tmp;
            }

            config->num_spoofs++;
        }
    }

    return 0;
}
