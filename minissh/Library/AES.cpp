//
//  AES.cpp
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

// AES, based on:
// http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
// http://www.infosecwriters.com/Papers/ABerent_AESbyExample.pdf

#include <memory.h>
#include "AES.h"

namespace AES_Internal {
    
    const Byte eSMap[] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };
    
    const Byte dSMap[] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    };
    
    const Byte gfE[] = {
        0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35,
        0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
        0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
        0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
        0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
        0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
        0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
        0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
        0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
        0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
        0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
        0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
        0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
        0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
        0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
        0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
    };
    
    const Byte gfL[] = {
        0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
        0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
        0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
        0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
        0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
        0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
        0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
        0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
        0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
        0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
        0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
        0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
        0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
        0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
        0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
        0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
    };
    
    const Byte encryptMatrix[] = {
        2,  3,  1,  1,
        1,  2,  3,  1,
        1,  1,  2,  3,
        3,  1,  1,  2,
    };
    
    const Byte decryptMatrix[] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e,
    };
    
    const UInt32 Rcon[] = {
        0x01000000,
        0x02000000,
        0x04000000,
        0x08000000,
        0x10000000,
        0x20000000,
        0x40000000,
        0x80000000,
        0x1B000000,
        0x36000000,
        0x6C000000,
        0xD8000000,
        0xAB000000,
        0x4D000000,
        0x9A000000,
    };
    
    class State {
    private:
        Byte _matrix[4 * 4];
        
        Byte At(int x, int y)
        {
            return _matrix[y + (x * 4)];
        }
        void Set(int x, int y, Byte b)
        {
            _matrix[y + (x * 4)] = b;
        }
        
        void ShiftRow(int row, int amount, bool left)
        {
            if (amount == 0)
                return;
            if (left) {
                Byte carry = At(0, row);
                for (int x = 0; x < 3; x++)
                    Set(x, row, At(x + 1, row));
                Set(3, row, carry);
            } else {
                Byte carry = At(3, row);
                for (int x = 3; x > 0; x--)
                    Set(x, row, At(x - 1, row));
                Set(0, row, carry);
            }
            ShiftRow(row, amount - 1, left);
        }
        
        static Byte GaloisFieldMultiply(Byte a, Byte b)
        {
            // Special cases
            if ((a == 0) || (b == 0))
                return 0;
            if (a == 1)
                return b;
            if (b == 1)
                return a;
            // Use lookup tables
            UInt32 ltotal = gfL[a] + gfL[b];
            if (ltotal > 0xFF)
                ltotal -= 0xFF;
            return gfE[ltotal];
        }
        
        static void DoMatrixMultiPart(Byte *column, const Byte *flippedMatrix)
        {
            Byte result[4];

            // Compute
            for (int i = 0; i < 16; i += 4)
                result[i / 4] = GaloisFieldMultiply(column[0], flippedMatrix[i + 0]) ^ GaloisFieldMultiply(column[1], flippedMatrix[i + 1]) ^ GaloisFieldMultiply(column[2], flippedMatrix[i + 2]) ^ GaloisFieldMultiply(column[3], flippedMatrix[i + 3]);
            // Copy back into input
            for (int i = 0; i < 4; i++)
                column[i] = result[i];
        }
        
    public:
        State(sshBlob *input)
        {
            if (input->Length() != sizeof(_matrix))
                throw "Invalid state";
            memcpy(_matrix, input->Value(), sizeof(_matrix));
        }
        
        void SubBytes(bool encrypt)
        {
            const Byte *data = encrypt ? eSMap : dSMap;
            for (int i = 0; i < sizeof(_matrix); i++)
                _matrix[i] = data[_matrix[i]];
        }
        
        void ShiftRows(bool encrypt)
        {
            for (int y = 0; y < 4; y++)
                ShiftRow(y, y, encrypt);
        }
        
        void AddRoundKey(sshBlob *key, int offset)
        {
            offset *= sizeof(_matrix);
            if ((key->Length() - offset) < sizeof(_matrix))
                throw "Expanded key too short";
            const Byte *other = key->Value() + offset;
            for (int i = 0; i < sizeof(_matrix); i++)
                _matrix[i] ^= other[i];
        }
        
        void MixColumns(bool encrypt)
        {
            const Byte *data = encrypt ? encryptMatrix : decryptMatrix;
            for (int i = 0; i < 16; i += 4)
                DoMatrixMultiPart(_matrix + i, data);
        }
        
        sshBlob* Data(void)
        {
            sshBlob *result = new sshBlob();
            result->Append(_matrix, sizeof(_matrix));
            result->Autorelease();
            return result;
        }
    };
    
    class Word
    {
    private:
        Byte _a, _b, _c, _d;
        
    public:
        static Word From(Byte a, Byte b, Byte c, Byte d)
        {
            Word result;
            result._a = a;
            result._b = b;
            result._c = c;
            result._d = d;
            return result;
        }
        
        static Word From(UInt32 v)
        {
            Word result;
            result._a = (v & 0xFF000000) >> 24;
            result._b = (v & 0xFF0000) >> 16;
            result._c = (v & 0xFF00) >> 8;
            result._d = v & 0xFF;
            return result;
        }
        
        Word RotWord(void)
        {
            return From(_b, _c, _d, _a);
        }
        
        Word SubWord(void)
        {
            return From(eSMap[_a], eSMap[_b], eSMap[_c], eSMap[_d]);
        }
        
        Word Xor(Word x)
        {
            return From(_a ^ x._a, _b ^ x._b, _c ^ x._c, _d ^ x._d);
        }
        
        void AddTo(sshBlob *out)
        {
            out->Append(&_a, sizeof(_a));
            out->Append(&_b, sizeof(_b));
            out->Append(&_c, sizeof(_c));
            out->Append(&_d, sizeof(_d));
        }
    };
}

static sshBlob* ExpandKey(sshBlob *keyBlob, int rounds)
{
    int expansionRounds = 4 * (rounds + 1);
    AES_Internal::Word result[expansionRounds];
    AES_Internal::Word temp;
    const Byte *key = keyBlob->Value();
    int Nk = keyBlob->Length() / 4;
    
    int i = 0;
    while (i < Nk) {
        int base = i * 4;
        result[i] = AES_Internal::Word::From(key[base + 0], key[base + 1], key[base + 2], key[base + 3]);
        i++;
    }
    
    while (i < expansionRounds) {
        temp = result[i - 1];
        if ((i % Nk) == 0)
            temp = temp.RotWord().SubWord().Xor(AES_Internal::Word::From(AES_Internal::Rcon[(i / Nk) - 1]));
        else if ((Nk > 6) && ((i % Nk) == 4))
            temp = temp.SubWord();
        result[i] = result[i - Nk].Xor(temp);
        i++;
    }
    
    // TODO: Should be possible to just add result?
    sshBlob *bResult = new sshBlob();
    for (int j = 0; j < (sizeof(result) / sizeof(result[0])); j++)
        result[j].AddTo(bResult);
    bResult->Autorelease();
    return bResult;
}

AES::AES(sshBlob *key)
:Encryption(key)
{
    switch(key->Length()) {
        case 16:
            _rounds = 10;
            break;
        case 24:
            _rounds = 12;
            break;
        case 32:
            _rounds = 14;
            break;
        default:
            throw "Invalid key length";
    }
    _expandedKey = ExpandKey(key, _rounds);
    _expandedKey->AddRef();
}

AES::~AES()
{
    _expandedKey->Release();
}

sshBlob* AES::Encrypt(sshBlob *data)
{
    AES_Internal::State state(data);
    state.AddRoundKey(_expandedKey, 0);
    for (int roundCount = 1; roundCount < _rounds; roundCount++) {
        state.SubBytes(true);
        state.ShiftRows(true);
        state.MixColumns(true);
        state.AddRoundKey(_expandedKey, roundCount);
    }
    state.SubBytes(true);
    state.ShiftRows(true);
    state.AddRoundKey(_expandedKey, _rounds);
    return state.Data();
}

sshBlob* AES::Decrypt(sshBlob *data)
{
    AES_Internal::State state(data);
    state.AddRoundKey(_expandedKey, _rounds);
    for (int roundCount = _rounds - 1; roundCount > 0; roundCount--) {
        state.ShiftRows(false);
        state.SubBytes(false);
        state.AddRoundKey(_expandedKey, roundCount);
        state.MixColumns(false);
    }
    state.ShiftRows(false);
    state.SubBytes(false);
    state.AddRoundKey(_expandedKey, 0);
    return state.Data();
}
