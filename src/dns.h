/* ========================================================================
   $HEADER FILE
   $File: dns.h $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/28 $
   $Description: $
   $Revisions: $
   ======================================================================== */

#if !defined(DNS_H)
#define DNS_H

#include <stdint.h>

struct DNSQuestion
{
    char *Name;
    uint16_t Type;
    uint16_t Class;
};

struct DNSAnswer
{
    char *Name;
    uint16_t Type;
    uint16_t Class;
    uint32_t TTL;
    uint16_t RDataLength;
    char *RData;
};

struct DNS
{
    uint16_t TransactionID;
    uint16_t Flags;
    uint16_t QuestionCount;
    uint16_t AnswerCount;
    uint16_t AuthorityCount;
    uint16_t AdditionalCount;

    DNSQuestion *Questions;
    DNSAnswer *Answers;
};

int DNSCreate(DNS *response, char *buffer);
int DNSParse(char *buffer, uint32_t length, DNS *response);
void DNSDestroy(DNS **query);

#endif
