//
//  DiffieHellman.cpp
//  minissh
//
//  Created by Colin David Munro on 31/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "DiffieHellman.h"
#include "Maths.h"
#include "SshNumbers.h"
#include "RSA.h"
#include "Hash.h"
#include "Primes.h"

namespace minissh::Algorithms::DiffieHellman {

namespace {
    
Hash::SHA1 hash;
    
} // namespace
    
bool Base::CheckRange(const Maths::BigNumber &number)
{
    return (number >= 1) && (number <= (_p - 1));
}

Base::Base(Transport::Transport& owner, Transport::Mode mode, Maths::BigNumber p, Maths::BigNumber g)
:KeyExchanger(owner, mode, hash), _p(p), _g(g)
{
    Byte message = (_mode == Transport::Server) ? KEXDH_INIT : KEXDH_REPLY;
    _owner.RegisterForPackets(this, &message, 1);
}

Base::~Base()
{
    Byte message = (_mode == Transport::Server) ? KEXDH_INIT : KEXDH_REPLY;
    _owner.UnregisterForPackets(&message, 1);
}

Types::Blob Base::MakeHash(void)
{
    Types::Blob input;
    Types::Writer writer(input);
    bool isClient = _mode == Transport::Client;
    const Transport::Internal::TransportInfo &client(isClient ? _owner.local : _owner.remote);
    const Transport::Internal::TransportInfo &server(isClient ? _owner.remote : _owner.local);
    writer.WriteString(client.version);
    writer.WriteString(server.version);
    writer.WriteString(client.kexPayload);
    writer.WriteString(server.kexPayload);
    writer.WriteString(SaveSSHKeys(_hostKey, false));
    writer.Write(_e);
    writer.Write(_f);
    writer.Write(key);
    std::optional<Types::Blob> result = _hash.Compute(input);
    if (!result)
        throw new std::runtime_error("Failed to create hash");
#ifdef DEBUG_KEX
    printf("Hash content:\n");
    input.DebugDump();
    printf("Hash output:\n");
    result->DebugDump();
#endif
    return *result;
}

void Base::Start(void)
{
    do {
        Maths::Primes::ST_Random_Prime_Result result = Maths::Primes::ST_Random_Prime(_p.BitLength(), Maths::BigNumber(_p.BitLength(), _owner.random), Hash::SHA1());
        if (!result.status)
            continue;
        _xy = result.prime;
    } while (!CheckRange(_xy));
    
    Maths::BigNumber ef = _g.PowerMod(_xy, _p);
    
    switch (_mode) {
        case Transport::Client:
            _e = ef;
        {
            Types::Blob payload;
            Types::Writer writer(payload);
            writer.Write(KEXDH_INIT);
            writer.Write(_e);
            _owner.Send(payload);
        }
            break;
        case Transport::Server:
            _f = ef;
            break;
    }
}

void Base::HandlePayload(Types::Blob data)
{
    Types::Reader reader(data);
    
    switch (reader.ReadByte()) {
        case KEXDH_INIT:
            _hostKey = _owner.GetHostKey();
            if (_mode != Transport::Server)
                _owner.Panic(Transport::Transport::PanicReason::InvalidMessage);
            if (!_hostKey)
                _owner.Panic(Transport::Transport::PanicReason::NoHostKey);
            _e = reader.ReadMPInt();
            // Compute key
            if (!CheckRange(_e))
                _owner.Panic(Transport::Transport::PanicReason::OutOfRange);
            key = _e.PowerMod(_xy, _p);
            // Calculate hash
            exchangeHash = MakeHash();
            if (!_owner.sessionID)
                _owner.sessionID = exchangeHash;
            // Generate keys
            GenerateKeys();
            // Reply
        {
            Types::Blob reply;
            Types::Writer writer(reply);
            writer.Write(KEXDH_REPLY);
            writer.WriteString(Files::Format::SaveSSHKeys(_hostKey, false));
            writer.Write(_f);
            writer.WriteString(_owner.hostKeyAlgorithm->Compute(*_hostKey, exchangeHash));
            _owner.Send(reply);
        }
            // After replying, generate 'new keys' message indicating we want to use new keys, and start using them
            NewKeys();
            break;
        case KEXDH_REPLY:
            if (_mode != Transport::Client)
                _owner.Panic(Transport::Transport::PanicReason::InvalidMessage);
            _hostKey = Files::Format::LoadSSHKeys(reader.ReadString());
            if (!_hostKey)
                _owner.Panic(Transport::Transport::PanicReason::BadHostKey);
            _f = reader.ReadMPInt();
            Types::Blob signature = reader.ReadString();
            // Compute key
            if (!CheckRange(_f))
                _owner.Panic(Transport::Transport::PanicReason::OutOfRange);
            key = _f.PowerMod(_xy, _p);
            // Calculate hash
            exchangeHash = MakeHash();
            if (!_owner.sessionID)
                _owner.sessionID = exchangeHash;
            // Check signature
            if (!_owner.hostKeyAlgorithm->Confirm(*_hostKey)) {
                _owner.Panic(Transport::Transport::PanicReason::BadHostKey);
                return;
            }
            if (!_owner.hostKeyAlgorithm->Verify(*_hostKey, signature, exchangeHash)) {
                _owner.Panic(Transport::Transport::PanicReason::BadSignature);
                return;
            }
            // Now we have the hash, we can calculate the keys, and activate them
            GenerateKeys();
            NewKeys();
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

namespace {
    
const UInt32 diffieHellman_group1[] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
    0xFFFFFFFF, 0xFFFFFFFF
};
    
} // namespace

Group1::Group1(Transport::Transport& owner, Transport::Mode mode)
:Base(owner, mode, Maths::BigNumber(diffieHellman_group1, sizeof(diffieHellman_group1) / sizeof(diffieHellman_group1[0]), true), Maths::BigNumber(2))
{
}

namespace {
    
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

} // namespace
    
Group14::Group14(Transport::Transport& owner, Transport::Mode mode)
:Base(owner, mode, Maths::BigNumber(diffieHellman_group14, sizeof(diffieHellman_group14) / sizeof(diffieHellman_group14[0]), true), Maths::BigNumber(2))
{
}

} // namespace minissh::Algorithms::DiffieHellman
