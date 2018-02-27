/* ========================================================================
   $SOURCE FILE
   $File: dns.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/28 $
   $Functions: $
static int DNSReadName(char *buffer, char **output)
static int DNSWriteName(char *input, char *output)
int DNSCreate(DNS *query, char *buffer)
int DNSParse(char *buffer, uint32_t length, DNS *query)
void DNSDestroy(DNS *query)

   $Description: This file contains all functions to do with parsing/creating DNS queries. $
   $Revisions: $
   ======================================================================== */

#include "dns.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
   $ FUNCTION
   $ Name: int DNSReadName $
   $ Prototype: static int DNSReadName(char *buffer, char **output) $
   $ Params: 
   $    buffer: The buffer to read $
   $    output: The output buffer to write to $
   $ Description: This function reads a hostname in the DNS naming format $
   ======================================================================== */
static int DNSReadName(char *buffer, char **output)
{
    int length = strlen(buffer) - 1;

    *output = (char*)malloc(length + 1);
    char *out = *output;

    int len = 0;
    for(int i = 0; i < length; i += len + 1)
    {
        if (len != 0)
        {
            *out++ = '.';
        }
        len = buffer[i];
        if (len < 0)
        {
            return -1;
        }
        for(int j = 0; j < len; j++)
        {
            *out++ = buffer[i + j + 1];
        }
    }
    *out++ = 0;

    return length + 2;
}

/* ========================================================================
   $ FUNCTION
   $ Name: int DNSWriteName $
   $ Prototype: static int DNSWriteName(char *input, char *output) $
   $ Params: 
   $    input: The input hostname $
   $    output: The ouput to write to $
   $ Description: This function converts a normal URL into a DNS format $
   ======================================================================== */
static int DNSWriteName(char *input, char *output)
{
    int length = strlen(input);
    char *start = output;

    int lock = 0;
    for(int i = 0; i < length; i++)
    {
        if (input[i] == '.')
        {
            *output++ = i - lock;
            for(; lock < i; lock++)
            {
                *output++ = input[lock];
            }
            lock++;
        }
    }
    *output++ = length - lock;
    for(; lock < length; lock++)
    {
        *output++ = input[lock];
    }
    *output++ = 0;

    return (uint32_t)(output - start);
}

/* ========================================================================
   $ FUNCTION
   $ Name: DNSCreate $
   $ Prototype: int DNSCreate(DNS *query, char *buffer) $
   $ Params: 
   $    query: The DNS query struct to put into the buffer $
   $    buffer: The buffer to write to $
   $ Description: This function converts the DNS struct into a character array $
   ======================================================================== */
int DNSCreate(DNS *query, char *buffer)
{

    char *start = buffer;

    *((uint16_t*)buffer) = htons(query->TransactionID);
    buffer += 2;
    *((uint16_t*)buffer) = htons(query->Flags);
    buffer += 2;
    *((uint16_t*)buffer) = htons(query->QuestionCount);
    buffer += 2;
    *((uint16_t*)buffer) = htons(query->AnswerCount);
    buffer += 2;
    *((uint16_t*)buffer) = htons(query->AuthorityCount);
    buffer += 2;
    *((uint16_t*)buffer) = htons(query->AdditionalCount);
    buffer += 2;

    // Questions
    for(int i = 0; i < query->QuestionCount; i++)
    {
        buffer += DNSWriteName(query->Questions[i].Name, buffer);

        *((uint16_t*)buffer) = htons(query->Questions[i].Type);
        buffer += 2;
        *((uint16_t*)buffer) = htons(query->Questions[i].Class);
        buffer += 2;

    }

    // Answers
    for(int i = 0; i < query->AnswerCount; i++)
    {
        // pointer
        buffer += 2;

        *((uint16_t*)buffer) = htons(query->Answers[i].Type);
        buffer += 2;
        *((uint16_t*)buffer) = htons(query->Answers[i].Class);
        buffer += 2;
        *((uint32_t*)buffer) = htonl(query->Answers[i].TTL);
        buffer += 4;
        *((uint16_t*)buffer) = htons(query->Answers[i].RDataLength);
        buffer += 2;

        memcpy(buffer, query->Answers[i].RData, query->Answers[i].RDataLength);
        buffer += query->Answers[i].RDataLength;

    }

    return (int)(buffer - start);
}

/* ========================================================================
   $ FUNCTION
   $ Name: DNSParse $
   $ Prototype: int DNSParse(char *buffer, uint32_t length, DNS *query) $
   $ Params: 
   $    buffer: The buffer to read from $
   $    length: The length of the buffer $
   $    query: The DNS query struct to write to $
   $ Description: This function parses a DNS packet into a struct $
   ======================================================================== */
int DNSParse(char *buffer, uint32_t length, DNS *query)
{
    char *pos = buffer;

    if (length < 12)
    {
        printf("Error. buffer length is too short for an DNS Header.\n");
        return -1;
    }

    query->TransactionID = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->Flags = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->QuestionCount = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->AnswerCount = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->AuthorityCount = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->AdditionalCount = ntohs(*(uint16_t*)pos);
    pos += 2;

    query->Questions = 0;
    query->Answers = 0;

    if (query->QuestionCount > 0)
    {
        query->Questions = (DNSQuestion*)malloc(sizeof(DNSQuestion) * query->QuestionCount);

        for(int i = 0; i < query->QuestionCount; i++)
        {
            int tmp = DNSReadName(pos, &query->Questions[i].Name);
            if (tmp == -1)
            {
                return -1;
            }
            pos += tmp;
            query->Questions[i].Type = ntohs(*(uint16_t*)pos);
            pos += 2;

            query->Questions[i].Class = ntohs(*(uint16_t*)pos);
            pos += 2;
        }
    }

    if (query->AnswerCount > 0)
    {
        query->Answers = (DNSAnswer*)malloc(sizeof(DNSAnswer) * query->AnswerCount);

        for(int i = 0; i < query->AnswerCount; i++)
        {
            // Check if the name is a DNS Name String or a pointer.
            uint16_t ptr = ntohs(*(uint16_t*)pos);
            if ((ptr & 0xc000) == 0xc000)
            {
                ptr &= 0x3FFF;
                DNSReadName(buffer + ptr, &query->Answers[i].Name);
                pos += 2;
            }
            else
            {
                printf("ReadName Answer NOT IMPLEMENTED!\n");
                return -1;
            }

            query->Answers[i].Type = ntohs(*(uint16_t*)pos);
            pos += 2;

            query->Answers[i].Class = ntohs(*(uint16_t*)pos);
            pos += 2;

            query->Answers[i].TTL = ntohl(*(uint32_t*)pos);
            pos += 4;

            query->Answers[i].RDataLength = ntohs(*(uint16_t*)pos);
            pos += 2;

            query->Answers[i].RData = (char*)malloc(query->Answers[i].RDataLength);
            memcpy(query->Answers[i].RData, pos, query->Answers[i].RDataLength);
            pos += query->Answers[i].RDataLength;
        }
    }

    return 0;
}

/* ========================================================================
   $ FUNCTION
   $ Name: DNSDestroy $
   $ Prototype: void DNSDestroy(DNS *query) $
   $ Params: 
   $    query: The query to destroy $
   $ Description: This function cleans up a DNS query struct $
   ======================================================================== */
void DNSDestroy(DNS **query)
{
    free(*query);
    free((*query)->Questions);
    free((*query)->Answers);
}
