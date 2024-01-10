#include <stdbool.h>

#ifndef DEBUG
#define DEBUG false
#endif

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;

int set_checksum(u8 *buf, size_t offset, size_t len);
int checksum(const u8 *buf, size_t len);
bool smbios_decode_check (const u8 *buf);

bool set_checksums(u8 *buf);
