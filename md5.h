#ifndef MD5_H
#define MD5_H

#include <stdint.h>

typedef unsigned char byte_t;

typedef struct {
   byte_t buffer[64];
   uint32_t bufsize;
   unsigned long long bitsize;
   uint32_t rawhash[4];
} md5_t;

void md5_init (md5_t* self);
void md5_update (md5_t* self, byte_t* data, size_t length);
void md5_hash (md5_t* self, uint32_t hash[4]);

#endif // MD5_H
