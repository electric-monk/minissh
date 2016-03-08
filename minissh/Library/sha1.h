/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

#ifndef __SHA1_H
#define __SHA1_H

#include "Types.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    typedef struct {
        UInt32 state[5];
        UInt32 count[2];
        Byte  buffer[64];
    } SHA1_CTX;
    
#define SHA1_DIGEST_SIZE 20
    
    void SHA1_Init(SHA1_CTX* context);
    void SHA1_Update(SHA1_CTX* context, const Byte* data, const size_t len);
    void SHA1_Final(SHA1_CTX* context, Byte digest[SHA1_DIGEST_SIZE]);
    
#ifdef __cplusplus
}
#endif

#endif /* __SHA1_H */
