//
//  DiffieHellman.cpp
//  minissh
//
//  Created by Colin David Munro on 31/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "DiffieHellman.h"
#include "Maths.h"
#include "SshNumbers.h"
#include "RSA.h"
#include "Hash.h"

bool diffieHellman::CheckRange(LargeNumber *number)
{
    LargeNumber *one = new LargeNumber(1);
    if (one->Compare(number) < 0) {
        one->Release();
        return false;
    }
    LargeNumber *pMinus1 = Prime()->Subtract(one);
    one->Release();
    return number->Compare(pMinus1) > 0;
}

diffieHellman::diffieHellman(sshTransport *owner, TransportMode mode)
:sshKeyExchanger(owner, mode)
{
    Byte message = (_mode == Server) ? SSH_MSG_KEXDH_INIT : SSH_MSG_KEXDH_REPLY;
    _owner->RegisterForPackets(this, &message, 1);
    _e = NULL;
    _f = NULL;
    _xy = NULL;
}

diffieHellman::~diffieHellman()
{
    Byte message = (_mode == Server) ? SSH_MSG_KEXDH_INIT : SSH_MSG_KEXDH_REPLY;
    _owner->UnregisterForPackets(&message, 1);
    if (_e)
        _e->Release();
    if (_f)
        _f->Release();
    if (_xy)
        _xy->Release();
}

sshString* diffieHellman::MakeHash(void)
{
    sshBlob *input = new sshBlob();
    sshWriter writer(input);
    sshTransport_Internal::TransportInfo *client, *server;
    if (_mode == Client) {
        client = &_owner->local;
        server = &_owner->remote;
    } else {
        client = &_owner->remote;
        server = &_owner->local;
    }
    writer.Write(client->version);
    writer.Write(server->version);
    writer.Write(client->kexPayload->AsString());
    writer.Write(server->kexPayload->AsString());
    writer.Write(_hostKey);
    writer.Write(_e);
    writer.Write(_f);
    writer.Write(key);
    sshBlob *result = hash->Compute(input);
#ifdef DEBUG_KEX
    printf("Hash content:\n");
    input->DebugDump();
    printf("Hash output:\n");
    result->DebugDump();
#endif
    input->Release();
    sshString *string = new sshString(result);
    string->Autorelease();
    return string;
}

void diffieHellman::Start(void)
{
    LargeNumber *p = Prime();
    LargeNumber *g = Generator();
    _xy = NULL;
    do {
        if (_xy)
            _xy->Release();
        _xy = new LargeNumber(p->Length(), _owner->random, 0);
    } while (!CheckRange(_xy));
    
    LargeNumber *ef = g->PowerMod(_xy, p);
    ef->AddRef();
    
    switch (_mode) {
        case Client:
            _e = ef;
        {
            sshBlob *payload = new sshBlob();
            sshWriter writer(payload);
            writer.Write((Byte)SSH_MSG_KEXDH_INIT);
            writer.Write(_e);
            _owner->Send(payload);
            payload->Release();
        }
            break;
        case Server:
            _f = ef;
            break;
    }
}

void diffieHellman::HandlePayload(sshBlob *data)
{
    sshReader reader(data);
    
    switch (reader.ReadByte()) {
        case SSH_MSG_KEXDH_INIT:
            if (_mode != Server)
                _owner->Panic(sshTransport::prInvalidMessage);
            _e = reader.ReadMPInt();
            _e->AddRef();
            // Compute key
//            if (!CheckRange(_e))
//                _owner->Panic(sshTransport::prOutOfRange);
            key = _e->PowerMod(_xy, Prime());
            key->AddRef();
            // Reply
            
            break;
        case SSH_MSG_KEXDH_REPLY:
            if (_mode != Client)
                _owner->Panic(sshTransport::prInvalidMessage);
            _hostKey = reader.ReadString();
            _hostKey->AddRef();
            _f = reader.ReadMPInt();
            _f->AddRef();
            sshString *_signature = reader.ReadString();
            _signature->AddRef();
            // Compute key
            if (!CheckRange(_f))
                _owner->Panic(sshTransport::prOutOfRange);
            key = _f->PowerMod(_xy, Prime());
            key->AddRef();
            // Calculate hash
            exchangeHash = MakeHash();
            exchangeHash->AddRef();
            if (_owner->sessionID == NULL) {
                _owner->sessionID = exchangeHash;
                _owner->sessionID->AddRef();
            }
            // Check signature
            if (!_owner->hostKeyAlgorithm->Confirm(_hostKey)) {
                _owner->Panic(sshTransport::prBadHostKey);
                return;
            }
            if (!_owner->hostKeyAlgorithm->Verify(_hostKey, _signature, exchangeHash)) {
                _owner->Panic(sshTransport::prBadSignature);
                return;
            }
            // Now we have the key, we can activate it
            GenerateKeys();
            break;
    }
}

// RFC2412
//
//E.2. Well-Known Group 2:  A 1024 bit prime
//
//The prime is 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
//Its decimal value is
//179769313486231590770839156793787453197860296048756011706444
//423684197180216158519368947833795864925541502180565485980503
//646440548199239100050792877003355816639229553136239076508735
//759914822574862575007425302077447712589550957937778424442426
//617334727629299387668709205606050270810842907692932019128194
//
//The primality of the number has been rigorously proven.
//
//The representation of the group in OAKLEY is
//Type of group:                    "MODP"
//Size of field element (bits):      1024
//Prime modulus:                     21 (decimal)
//Length (32 bit words):          32
//Data (hex):
//FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
//29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
//EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
//E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
//EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
//FFFFFFFF FFFFFFFF
//Generator:                         22 (decimal)
//Length (32 bit words):          1
//Data (hex):                     2
//
//Optional Parameters:
//Group order largest prime factor:  24 (decimal)
//Length (32 bit words):          32
//Data (hex):
//7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68
//94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E
//F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122
//F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6
//F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F67329C0
//FFFFFFFF FFFFFFFF
//Strength of group:                 26 (decimal)
//Length (32 bit words)            1
//Data (hex):
//0000004D

static SHA1 dh_hash;

const UInt32 diffieHellman_group1[] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
    0xFFFFFFFF, 0xFFFFFFFF
};

dhGroup1::dhGroup1(sshTransport *owner, TransportMode mode)
:diffieHellman(owner, mode)
{
    hash = &dh_hash;
}

LargeNumber* dhGroup1::Prime(void)
{
    LargeNumber *result = new LargeNumber(diffieHellman_group1, sizeof(diffieHellman_group1) / sizeof(diffieHellman_group1[0]), true);
    result->Autorelease();
    return result;
}

LargeNumber* dhGroup1::Generator(void)
{
    LargeNumber *result = new LargeNumber(2);
    result->Autorelease();
    return result;
}

const UInt32 diffieHellman_group14[] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE45B3D,
    0xC2007CB8, 0xA163BF05, 0x98DA4836, 0x1C55D39A, 0x69163FA8, 0xFD24CF5F,
    0x83655D23, 0xDCA3AD96, 0x1C62F356, 0x208552BB, 0x9ED52907, 0x7096966D,
    0x670C354E, 0x4ABC9804, 0xF1746C08, 0xCA18217C, 0x32905E46, 0x2E36CE3B,
    0xE39E772C, 0x180E8603, 0x9B2783A2, 0xEC07A28F, 0xB5C55DF0, 0x6F4C52C9,
    0xDE2BCBF6, 0x95581718, 0x3995497C, 0xEA956AE5, 0x15D22618, 0x98FA0510,
    0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF
};

dhGroup14::dhGroup14(sshTransport *owner, TransportMode mode)
:diffieHellman(owner, mode)
{
    hash = &dh_hash;
}

LargeNumber* dhGroup14::Prime(void)
{
    LargeNumber *result = new LargeNumber(diffieHellman_group14, sizeof(diffieHellman_group14) / sizeof(diffieHellman_group14[0]), true);
    result->Autorelease();
    return result;
}

LargeNumber* dhGroup14::Generator(void)
{
    LargeNumber *result = new LargeNumber(2);
    result->Autorelease();
    return result;
}
