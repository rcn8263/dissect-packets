//
// file: dissectPackets.c
// description: reads a binary file of packets, prints the number of packets in 
// the file, and then the header data of each packet, which is preceded by a 
// one integer 'heading'.
//
// @author Ryan Nowak rcn8263
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER 2048 //Maximum length of a packet

int main(int argc, void *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: dissectPackets inputFile\n");
        return EXIT_FAILURE;
    }
    
    FILE *file;
    file = fopen(argv[1], "rb");
    //File does not exist / could not be opened
    if (file == NULL) {
        fprintf(stderr, "Failed to open input file: No such file or directory\n");
        return EXIT_FAILURE;
    }
    else {
        //get number of packets
        int packet_count;
        
        //Unable to read next part of file or end of file
        if (fread(&packet_count, sizeof(packet_count), 1, file) != 1) {
            fprintf(stderr, "Failed to read count of packets.\n");
            return EXIT_FAILURE;
        }
        //There are 0 packets of data in the file
        if (packet_count == 0) {
            printf("==== File %s contains 0 Packets.\n", argv[1]);
            return EXIT_SUCCESS;
        }
        printf("==== File %s contains %d Packets.\n", (char *) argv[1], packet_count);
        
        //Get and print individual packets
        for (int i = 1; i <= packet_count; i++) {
            printf("==>Packet %d\n", i);
            
            //Get Packet Length
            int packet_length;
            fread(&packet_length, sizeof(packet_length), 1, file);
            
            //Get Packet Data
            unsigned char packet_data[BUFFER] = "\0";
            fread(&packet_data, sizeof(char), packet_length, file);
            
            //Print Version
            printf("Version:\t\t%#03x (%hu)\n", 
                packet_data[0] >> 4, packet_data[0] >> 4);
            
            //Print IHL (Header Length)
            printf("IHL (Header Length):\t\t%#03x (%hu)\n", 
                packet_data[0]&0x0f, packet_data[0]&0x0f);
            
            //Print Type of Service (TOS)
            printf("Type of Service (TOS):\t\t0x%x (%hu)\n", 
                packet_data[1], packet_data[1]); 
            
            //Print Total Length
            char *length = (packet_data[2] << 8) | (packet_data[3]);
            printf("Total Length:\t\t%#04x (%hu)\n", length, length);
            
            //Print Identification
            int ident = (packet_data[4] << 8) | (packet_data[5]);
            char *identification = (packet_data[4] << 8) | (packet_data[5]);
            printf("Identification:\t\t");
            if (ident == 0) 
                printf("0x%x (%hu)\n", identification, identification);
            else 
                printf("%#06x (%hu)\n", identification, identification);
            
            //Print IP Flags
            printf("IP Flags:\t\t0x%x (%hu)\n", 
                packet_data[6], packet_data[6]);
            
            //Print Fragment Offset
            int offset = (packet_data[6]&0x1f) + packet_data[7];
            printf("Fragment Offset:\t\t");
            if (offset == 0) 
                printf("0x%x (%hu)\n", offset, offset);
            else 
                printf("%#03x (%hu)\n", offset, offset);
            
            //Print Time To Live (TTL)
            printf("Time To Live (TTL):\t\t%#04x (%hu)\n", 
                packet_data[8], packet_data[8]);
            
            //Print Protocol
            int id = packet_data[9];
            printf("Protocol:\t\t");
            if (id == 1) 
                printf("ICMP ");
            else if (id == 2) 
                printf("IGMP ");
            else if (id == 6) 
                printf("TCP ");
            else if (id == 9) 
                printf("IGRP ");
            else if (id == 17) 
                printf("UDP ");
            else if (id == 47) 
                printf("GRE ");
            else if (id == 50) 
                printf("ESP ");
            else if (id == 51) 
                printf("AH ");
            else if (id == 57) 
                printf("SKIP ");
            else if (id == 88) 
                printf("EIGRP ");
            else if (id == 89) 
                printf("OSPF ");
            else if (id == 115) 
                printf("L2TP ");
            printf("%#03x (%hu)\n", packet_data[9], packet_data[9]);
            
            //Print Header Checksum
            char *checksum = (packet_data[10] << 8) | (packet_data[11]);
            printf("Header Checksum:\t\t%#04x (%hu)\n", checksum, checksum);
            
            //Print Source Address
            printf("Source Address:\t\t%hu.%hu.%hu.%hu\n", 
                packet_data[12], packet_data[13], packet_data[14], packet_data[15]);
            
            //Print Destination Address
            printf("Destination Address:\t\t%hu.%hu.%hu.%hu\n", 
                packet_data[16], packet_data[17], packet_data[18], packet_data[19]);
            
        }
    }
    fclose(file);
    
    return EXIT_SUCCESS;
}