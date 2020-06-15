/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

#pragma once

#include "BaseTypes.h"

#define SHA1_DIGEST_SIZE 20

struct SHA1_CTX {
    minissh::UInt32 state[5];
    minissh::UInt32 count[2];
    minissh::Byte  buffer[64];
    
    void Init(void);
    void Update(const minissh::Byte* data, const size_t len);
    void Final(minissh::Byte digest[SHA1_DIGEST_SIZE]);
};
