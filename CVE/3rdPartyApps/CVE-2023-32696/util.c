#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "util.h"

/* based on dmidecode.c smbios_decode */
bool smbios_decode_check (const u8 *buf)
{
    if (!checksum(buf, buf[0x05])
         || memcmp(buf + 0x10, "_DMI_", 5) != 0
         || !checksum(buf + 0x10, 0x0F))
            return false;
    else
        return true;
}

bool set_checksums(u8 *buf)
{
    if (! checksum(buf, buf[0x5]))
        set_checksum(buf, 0, buf[0x5]);

    if (! checksum(buf + 0x10, 0x0F))
        set_checksum(buf, 0x10, 0x0F);

    return smbios_decode_check(buf);
}

/* The original DMI checksum function */
int checksum(const u8 *buf, size_t len)
{
    u8 sum = 0;
    size_t a;

    for (a = 0; a < len; a++)
        sum += buf[a];
    return (sum == 0);
}

/* Modified DMI checksum function. Sets buf[offset - 1] */
int set_checksum(u8 *buf, size_t offset, size_t len)
{

    u8 sum = 0;
    u8 prev_sum = 0;

    size_t a;

    if (DEBUG) {
        printf("Checksum from buf[%lu] to buf[%lu] --\n", offset, offset + len);

        printf("offset  n : sum   + buf[n]\n");
        printf("----------------------------------\n");
    }

    for (a = offset; a < offset + len; a++)
    {
        prev_sum = sum;
        sum += buf[a];

        if (DEBUG) {
            /* Show table */
            printf("offset %-3lu: %-5u + %-3d %% 256 = %3u", a, prev_sum, buf[a], sum);

            /* Only print sum on the last line */
            if (sum != 0 && (a == len-1))
                printf("\tmemset(buf+%lu, %d, 1); to fix checksum!\n\n", a, 256-prev_sum);
            else
                printf("\n");
        }

    }

    if (sum == 0) {
        if (DEBUG)
            printf("\n\nValid checksum!!\n");
        return true;
    }

    else {
        if (DEBUG)
            printf("You can also make the change at the first offset if the\n"
                    "rest of the array up to len is zero.\n\n");

        /* Automatically fix and re-validate */
        printf("\tSetting checksum: memset(buf+%lu, %d, 1);\n\n", a-1, 256-prev_sum);
        memset(buf+a-1, 256-prev_sum, 1);

        return checksum(buf+offset, len);

    }
}
