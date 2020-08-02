//
//  RSA.cpp (RFC3447)
//  minissh
//
//  Created by Colin David Munro on 2/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "RSA.h"
#include "Maths.h"
#include "Hash.h"
#include "DerFile.h"

namespace minissh::RSA {
    
namespace {
    
class KeyBaseReader : public Files::DER::Reader::Callback
{
protected:
    void Failed(void)
    {
        throw new std::runtime_error("Unexpected DER type");
    }
    void Invalid(void)
    {
        throw new std::runtime_error("File invalid; exponent/coefficient mismatch");
    }
private:
    int _start, _end, _cur;
public:
    KeyBaseReader()
    :_start(0), _end(0), _cur(0)
    {
    }
    
    void StartSequence(void) override
    {
        _start++;
    }
    void EndSequence(void) override
    {
        _end++;
    }
    void StartSet(void) override {Failed();}
    void EndSet(void) override {Failed();}
    void Unknown(Byte type, Types::Blob data) override {Failed();}
    void ReadNull(void) override {Failed();}
    void ReadObjectIdentifier(const std::vector<UInt32>& id) override {Failed();}
    void ReadInteger(Maths::BigNumber i) override
    {
        if ((_start == 1) && (_end == 0)) {
            GotNumber(_cur, i);
            _cur++;
        } else {
            Failed();
        }
    }
    virtual void GotNumber(int index, Maths::BigNumber value) = 0;
};

class KeyPublicReader : public KeyBaseReader
{
private:
    Maths::BigNumber *_numbers[2];
public:
    KeyPublicReader(Maths::BigNumber& n, Maths::BigNumber& e)
    :_numbers{&n, &e}
    {
    }
    
    void GotNumber(int index, Maths::BigNumber value) override
    {
        switch (index) {
            default:
                *_numbers[index] = value;
                break;
            case 2:
                Failed();
                break;
        }
    }
};

class KeySetReader : public KeyBaseReader
{
private:
    static constexpr int VERSION = 0;
    static constexpr int MODULUS = 1;
    static constexpr int EXPONENT_PUBLIC = 2;
    static constexpr int EXPONENT_PRIVATE = 3;
    static constexpr int PRIME1 = 4;
    static constexpr int PRIME2 = 5;
    static constexpr int EXPONENT1 = 6;
    static constexpr int EXPONENT2 = 7;
    static constexpr int COEFFICIENT = 8;
    
    Maths::BigNumber _version;
    Maths::BigNumber *_numbers[6];
public:
    KeySetReader(Maths::BigNumber& n, Maths::BigNumber& e, Maths::BigNumber& d, Maths::BigNumber& p, Maths::BigNumber& q)
    :_numbers{&_version, &n, &e, &d, &p, &q}
    {
    }
    
    void GotNumber(int index, Maths::BigNumber value) override
    {
        Maths::BigNumber temp;
        switch (index) {
            default:
                if ((index == VERSION) && (value != 0))
                    Invalid();
                *_numbers[index] = value;
                break;
            case EXPONENT1:
                temp = _numbers[EXPONENT_PRIVATE]->PowerMod(1, *_numbers[PRIME1] - 1);
                if (value != temp)
                    Invalid();
                break;
            case EXPONENT2:
                if (value != _numbers[EXPONENT_PRIVATE]->PowerMod(1, *_numbers[PRIME2] - 1))
                    Invalid();
                break;
            case COEFFICIENT:
                if (value != _numbers[PRIME2]->ModularInverse(*_numbers[PRIME1]))
                    Invalid();
                break;
            case 9:
                Failed();
                break;
        }
    }
};

constexpr const char* TEXT_SSH_RSA = "ssh-rsa";
constexpr const char* TEXT_DER_RSA_PUBLIC = "RSA PUBLIC KEY";
constexpr const char* TEXT_DER_RSA_PRIVATE = "RSA PRIVATE KEY";
    
Files::Format::KeyFileLoader privateDER(
    TEXT_DER_RSA_PRIVATE, Files::Format::FileType::DER,
    [](Types::Blob load){
        return std::make_shared<KeySet>(load, Files::Format::FileType::DER);
    }
);

Files::Format::KeyFileLoader publicSSH(
    TEXT_SSH_RSA, Files::Format::FileType::SSH,
    [](Types::Blob load){
        return std::make_shared<KeyPublic>(load, Files::Format::FileType::SSH);
    }
);

Files::Format::KeyFileLoader publicDER(
    TEXT_DER_RSA_PUBLIC, Files::Format::FileType::DER,
    [](Types::Blob load){
        return std::make_shared<KeyPublic>(load, Files::Format::FileType::DER);
    }
);

} // namespace

Key::Key(Maths::BigNumber n, Maths::BigNumber e)
{
    this->n = n;
    this->e = e;
}

// 5.2.1 RSASP1
Maths::BigNumber RSASP1(Key key, Maths::BigNumber m)
{
    // 1. If the message representative m is not between 0 and n - 1,
    //    output "message representative out of range" and stop.
    if ((m <= 0) || (m >= (key.n - 1)))
        throw "Error";
    
    // 2. The signature representative s is computed as follows.
    //   a. If the first form (n, d) of K is used, let s = m^d mod n.
    Maths::BigNumber s = m.PowerMod(key.e, key.n);
    
    //   b. If the second form (p, q, dP, dQ, qInv) and (r_i, d_i, t_i)
    //      of K is used, proceed as follows:
    //     i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
    //     ii.   If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.
    //     iii.  Let h = (s_1 - s_2) * qInv mod p.
    //     iv.   Let s = s_2 + q * h.
    //     v.    If u > 2, let R = r_1 and for i = 3 to u do
    //         1. Let R = R * r_(i-1).
    //         2. Let h = (s_i - s) * t_i mod r_i.
    //         3. Let s = s + R * h.
    // TODO!
    
    // 3. Output s.
    return s;
}

// 5.2.2 RSAVP1
Maths::BigNumber RSAVP1(const Key& key, const Maths::BigNumber& s)
{
    // 1. If the signature representative s is not between 0 and n - 1,
    //    output "signature representative out of range" and stop.
    if ((s <= 0) || (s >= (key.n - 1)))
        throw "Error";
    
    // 2. Let m = s^e mod n.
    Maths::BigNumber m = s.PowerMod(key.e, key.n);
    
    // 3. Output m.
    return m;
}

KeySet::KeySet(Maths::RandomSource& random, int bits)
{
    _p = Maths::BigNumber(bits, random, 100);
    _q = Maths::BigNumber(bits, random, 100);
    _n = _p * _q;
    _e = 65537;
    Maths::BigNumber on = (_p - 1) * (_q - 1);
    while (true) {
        if ((on % _e) != 0)
            break;
        do {
            _e = Maths::BigNumber(on.BitLength(), random, 100);
        } while (_e >= on);
    }
    _d = _e.ModularInverse(on);
}
    
KeyPublic::KeyPublic(Types::Blob load, Files::Format::FileType type)
{
    switch (type) {
        case Files::Format::FileType::SSH:
        {
            Types::Reader reader(load);
            if (reader.ReadString().AsString().compare(TEXT_SSH_RSA) != 0)
                throw new std::runtime_error("Not an SSH RSA public key");
            _e = reader.ReadMPInt();
            _n = reader.ReadMPInt();
            if (reader.Remaining())
                throw new std::runtime_error("Extra data found after SSH key data");
        }
            break;
        case Files::Format::FileType::DER:
        {
            KeyPublicReader reader(_n, _e);
            Files::DER::Reader::Load(load, reader);
        }
            break;
        default:
            throw new std::invalid_argument("Unsupported file type");
    }
}

Types::Blob KeyPublic::SavePublic(Files::Format::FileType type)
{
    switch (type) {
        case Files::Format::FileType::SSH:
        {
            // SSH file format:
            // string "ssh-rsa"
            // mpint  e (exponent)
            // mpint  n (modulus)
            Types::Blob result;
            Types::Writer writer(result);
            writer.WriteString(TEXT_SSH_RSA);
            writer.Write(_e);
            writer.Write(_n);
            return result;
        }
        case Files::Format::FileType::DER:
        {
            // DER file format:
            // RSAPublicKey ::= SEQUENCE {
            //     modulus           INTEGER,  -- n
            //     publicExponent    INTEGER   -- e
            // }
            Files::DER::Writer::Sequence sequence;
            sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_n));
            sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_e));
            return sequence.Save();
        }
        default:
            throw new std::invalid_argument("Unsupported file type");
    };
}

std::string KeyPublic::GetKeyName(Files::Format::FileType type, bool isPrivate)
{
    if (!isPrivate) {
        if (type == Files::Format::FileType::SSH)
            return TEXT_SSH_RSA;
        if (type == Files::Format::FileType::DER)
            return TEXT_DER_RSA_PUBLIC;
    }
    return KeyFile::GetKeyName(type, isPrivate);
}

KeySet::KeySet(Types::Blob load, Files::Format::FileType type)
{
    if (type != Files::Format::FileType::DER)
        throw new std::invalid_argument("Unsupported file type");
    KeySetReader reader(_n, _e, _d, _p, _q);
    Files::DER::Reader::Load(load, reader);
}
    
Types::Blob KeySet::SavePrivate(Files::Format::FileType type)
{
    if (type != Files::Format::FileType::DER)
        throw new std::invalid_argument("Unsupported file type");
    // DER File Format
    // RSAPrivateKey ::= SEQUENCE {
    //     version           Version,
    //     modulus           INTEGER,  -- n
    //     publicExponent    INTEGER,  -- e
    //     privateExponent   INTEGER,  -- d
    //     prime1            INTEGER,  -- p
    //     prime2            INTEGER,  -- q
    //     exponent1         INTEGER,  -- d mod (p-1)
    //     exponent2         INTEGER,  -- d mod (q-1)
    //     coefficient       INTEGER,  -- (inverse of q) mod p
    //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }
    Files::DER::Writer::Sequence sequence;
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(0));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_n));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_e));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_d));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_p));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_q));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_d.PowerMod(1, _p - 1)));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_d.PowerMod(1, _q - 1)));
    sequence.components.push_back(std::make_shared<Files::DER::Writer::Integer>(_q.ModularInverse(_p)));
    return sequence.Save();
}

std::string KeySet::GetKeyName(Files::Format::FileType type, bool isPrivate)
{
    if ((type == Files::Format::FileType::DER) && isPrivate)
        return TEXT_DER_RSA_PRIVATE;
    return KeyPublic::GetKeyName(type, isPrivate);
}
    
// prefixes
//    MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H.
//    MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H.
//    SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
//    SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
//    SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
//    SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
// TODO: Maybe replace these DER prefixes (which are dotted around the code) with calls to the new DER code

// 9.2 EMSA-PKCS1-v1_5
std::optional<Types::Blob> EMSA_PKCS1_V1_5(Types::Blob M, int emLen, const Hash::Type& hash)
{
    // 1. Apply the hash function to the message M to produce a hash value
    //    H:
    //       H = Hash(M).
    //    If the hash function outputs "message too long," output "message
    //    too long" and stop.
    std::optional<Types::Blob> H = hash.Compute(M);
    if (!H)
        throw new Exception("No result from hash");

    // 2. Encode the algorithm ID for the hash function and the hash value
    //    into an ASN.1 value of type DigestInfo (see Appendix A.2.4) with
    //    the Distinguished Encoding Rules (DER), where the type DigestInfo
    //    has the syntax
    //    DigestInfo ::= SEQUENCE {
    //        digestAlgorithm AlgorithmIdentifier,
    //        digest OCTET STRING
    //    }
    //    The first field identifies the hash function and the second
    //    contains the hash value.  Let T be the DER encoding of the
    //    DigestInfo value (see the notes below) and let tLen be the length
    //    in octets of T.
    Types::Blob T;
    Types::Writer tWriter(T);
    tWriter.Write(hash.EMSA_PKCS1_V1_5_Prefix());
    tWriter.Write(*H);
    int tLen = T.Length();

    // 3. If emLen < tLen + 11, output "intended encoded message length too
    //    short" and stop.
    if (emLen < tLen + 11)
        throw new Exception("Intended encoded message length too short");

    // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
    //    with hexadecimal value 0xff.  The length of PS will be at least 8
    //    octets.
    int PSlength = emLen - tLen - 3;

    // 5. Concatenate PS, the DER encoding T, and other padding to form the
    //    encoded message EM as
    //       EM = 0x00 || 0x01 || PS || 0x00 || T.
    Types::Blob EM;
    Types::Writer writer(EM);
    writer.Write(Byte(0x00));
    writer.Write(Byte(0x01));
    for (int i = 0; i < PSlength; i++)
        writer.Write(Byte(0xFF));
    writer.Write(Byte(0x00));
    writer.Write(T);

    // 6. Output EM.
    return EM;
}

Maths::BigNumber OS2IP(Types::Blob blob)
{
    return Maths::BigNumber(blob.Value(), blob.Length(), false);
}

Types::Blob I2OSP(Maths::BigNumber value, int k)
{
    Types::Blob result;
    if (result.Length() < k) {
        // Pad with 0
        Types::Blob newResult;
        Byte zero = 0;
        int required = k - result.Length();
        for (int i = 0; i < required; i++)
            newResult.Append(&zero, 1);
        newResult.Append(result.Value(), result.Length());
        result = newResult;
    }
    if (result.Length() > k) { // Unlikely this is required anymore
        int remove = result.Length() - k;
        Types::Blob stripped;
        stripped.Append(result.Value() + remove, result.Length() - remove);
        result = stripped;
    }
    return result;
}

// 8.2.1 Signature generation operation
std::optional<Types::Blob> SSA_PKCS1_V1_5::Sign(const Key& privateKey, Types::Blob M, const Hash::Type& hash)
{
    int k = (privateKey.n.BitLength() + 7) / 8;

    // 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
    //    operation (Section 9.2) to the message M to produce an encoded
    //    message EM of length k octets:
    //      EM = EMSA-PKCS1-V1_5-ENCODE (M, k).
    //    If the encoding operation outputs "message too long," output
    //    "message too long" and stop.  If the encoding operation outputs
    //    "intended encoded message length too short," output "RSA modulus
    //    too short" and stop.
    std::optional<Types::Blob> EM = EMSA_PKCS1_V1_5(M, k, hash);
    if (!EM)
        throw new Exception("No result from hash");

    // 2. RSA signature:
    //  a. Convert the encoded message EM to an integer message
    //     representative m (see Section 4.2):
    //       m = OS2IP (EM).
    Maths::BigNumber m = OS2IP(*EM);
    
    //  b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
    //     private key K and the message representative m to produce an
    //     integer signature representative s:
    //       s = RSASP1 (K, m).
    Maths::BigNumber s = RSASP1(privateKey, m);
    
    //  c. Convert the signature representative s to a signature S of
    //     length k octets (see Section 4.1):
    //       S = I2OSP (s, k).
    Types::Blob S = I2OSP(s, k);
    
    // 3. Output the signature S.
    return S;
}

// 8.2.2 Signature verification operation
bool SSA_PKCS1_V1_5::Verify(const Key& publicKey, Types::Blob M, Types::Blob S, const Hash::Type& hash)
{
    int k = (publicKey.n.BitLength() + 7) / 8;
    
    // 1. Length checking: If the length of the signature S is not k octets,
    //    output "invalid signature" and stop.
    if (S.Length() != k)
        return false;

    // 2. RSA verification:
    //    a. Convert the signature S to an integer signature representative
    //       s (see Section 4.2):
    //          s = OS2IP (S).
    Maths::BigNumber s = OS2IP(S);
    
    //    b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
    //       RSA public key (n, e) and the signature representative s to
    //       produce an integer message representative m:
    //          m = RSAVP1 ((n, e), s).
    //       If RSAVP1 outputs "signature representative out of range,"
    //       output "invalid signature" and stop.
    Maths::BigNumber m = RSAVP1(publicKey, s);
    
    //    c. Convert the message representative m to an encoded message EM
    //       of length k octets (see Section 4.1):
    //          EM = I2OSP (m, k).
    //       If I2OSP outputs "integer too large," output "invalid
    //       signature" and stop.
    Types::Blob EM = m.Data();
    if (EM.Length() < k) {
        // Pad with 0
        Types::Blob newEM;
        Byte zero = 0;
        int required = k - EM.Length();
        for (int i = 0; i < required; i++)
            newEM.Append(&zero, 1);
        newEM.Append(EM.Value(), EM.Length());
        EM = newEM;
    }
    if (EM.Length() > k) { // Unlikely this is required anymore
        int remove = EM.Length() - k;
        Types::Blob stripped(EM.Value() + remove, EM.Length() - remove);
        EM = stripped;
    }
    
    // 3. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
    //    operation (Section 9.2) to the message M to produce a second
    //    encoded message EM' of length k octets:
    //          EM' = EMSA-PKCS1-V1_5-ENCODE (M, k).
    //    If the encoding operation outputs "message too long," output
    //    "message too long" and stop.  If the encoding operation outputs
    //    "intended encoded message length too short," output "RSA modulus
    //    too short" and stop.
    std::optional<Types::Blob> EM_ = EMSA_PKCS1_V1_5(M, k, hash);
    if (!EM_)
        throw new Exception("Failed to encode");
    
    // 4. Compare the encoded message EM and the second encoded message EM'.
    //    If they are the same, output "valid signature"; otherwise, output
    //    "invalid signature."
    return EM.Compare(*EM_);
}

} // namespace minissh::RSA
