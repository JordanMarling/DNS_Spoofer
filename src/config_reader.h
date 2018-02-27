/* ========================================================================
   $HEADER FILE
   $File: config_reader.h $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/28 $
   $Description: $
   $Revisions: $
   ======================================================================== */

#if !defined(CONFIG_READER_H)
#define CONFIG_READER_H

#include <stdint.h>

struct DNSSpoof
{
    char *web_address;

    uint32_t web_addr_len;
    uint32_t ip_address;

    DNSSpoof *Next;
};

struct DNSConfig
{
    uint32_t num_spoofs;
    DNSSpoof *SpoofList;
};

int ConfigRead(const char *filename, DNSConfig *config);

#endif
