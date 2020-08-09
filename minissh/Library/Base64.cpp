//
//  Base64.cpp
//  libminissh
//
//  Created by Colin David Munro on 15/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "Base64.h"

namespace minissh::Files::Base64 {

namespace {

constexpr int blockSize = 4;
constexpr int rawSize = 3;
constexpr Byte padding = '=';
    
Byte ByteForBits(Byte bits)
{
    if (bits & ~0x3F)
        throw std::runtime_error("Invalid bits");
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[bits & 0x3F];
}

Byte BitsForByte(Byte byte)
{
    if ((byte >= 'A') && (byte <= 'Z'))
        return byte - 'A';
    if ((byte >= 'a') && (byte <= 'z'))
        return byte + 26 - 'a';
    if ((byte >= '0') && (byte <= '9'))
        return byte + 52 - '0';
    if (byte == '+')
        return 62;
    if (byte == '/')
        return 63;
    if (byte == padding) // not really valid, but to make the code simpler
        return 0;
    throw std::runtime_error("Invalid byte");
}
    
} // namespace
    
Types::Blob Encode(Types::Blob raw)
{
    Types::Blob result;
    const Byte *data = raw.Value();
    int total = raw.Length();
    for (int i = 0; i < total; i += rawSize) {
        int len = std::min(rawSize, total - i);
        Byte input[] = {0, 0, 0};
        for (int j = 0; j < len; j++)
            input[j] = data[i + j];
        UInt32 thing = (input[0] << 16) | (input[1] << 8) | (input[2] << 0);
        constexpr UInt32 blockBitSize = blockSize * 6;
        UInt32 bitLength = len * 8;
        for (int j = 0; j < blockBitSize; j += 6) {
            Byte r = (j < bitLength) ? ByteForBits((thing & 0xFC0000) >> 18) : padding;
            result.Append(&r, 1);
            thing <<= 6;
        }
    }
    return result;
}
    
Types::Blob Decode(Types::Blob text)
{
    Types::Blob result;
    const Byte *data = text.Value();
    int total = text.Length();
    for (int i = 0; i < total; i += blockSize) {
        Byte input[] = {padding, padding, padding, padding};
        int len = std::min(blockSize, total - i);
        for (int j = 0; j < len; j++)
            input[j] = data[i + j];
        UInt32 thing = (BitsForByte(input[0]) << 18) | (BitsForByte(input[1]) << 12) | (BitsForByte(input[2]) << 6) | (BitsForByte(input[3]) << 0);
        for (int j = 0; j < rawSize; j++) {
            if (input[j + 1] == padding)
                break;
            Byte v = (thing & 0xFF0000) >> 16;
            result.Append(&v, 1);
            thing <<= 8;
        }
    }
    return result;
}
    
} // namespace minissh::Files::Base64
