//
//  RSA.cpp (RFC3447)
//  minissh
//
//  Created by Colin David Munro on 2/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "RSA.h"
#include "Maths.h"
#include "Hash.h"

namespace RSA {
    Key::Key(LargeNumber *n, LargeNumber *e)
    {
        this->n = n;
        n->AddRef();
        this->e = e;
        e->AddRef();
    }
    Key::~Key()
    {
        n->Release();
        e->Release();
    }
    
    // 5.2.1 RSASP1
    LargeNumber* RSASP1(Key *key, LargeNumber *m)
    {
        // 1. If the message representative m is not between 0 and n - 1,
        //    output "message representative out of range" and stop.
        LargeNumber *zero = new LargeNumber(0);
        zero->Autorelease();
        LargeNumber *one = new LargeNumber(1);
        LargeNumber *n1 = key->n->Subtract(one);
        one->Release();
        if ((m->Compare(zero) <= 0) || (m->Compare(n1) >= 0))
            return NULL;
        
        // 2. The signature representative s is computed as follows.
        //   a. If the first form (n, d) of K is used, let s = m^d mod n.
        LargeNumber *s = m->PowerMod(key->e, key->n);
        
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
    LargeNumber* RSAVP1(Key *key, LargeNumber *s)
    {
        // 1. If the signature representative s is not between 0 and n - 1,
        //    output "signature representative out of range" and stop.
        LargeNumber *zero = new LargeNumber(0);
        bool overZero = zero->Compare(s) > 0;
        zero->Release();
        LargeNumber *one = new LargeNumber(1);
        LargeNumber *nMinus1 = key->n->Subtract(one);
        one->Release();
        bool underNMinus1 = s->Compare(nMinus1) > 0;
        if (!overZero || !underNMinus1)
            return NULL;
        
        // 2. Let m = s^e mod n.
        LargeNumber *m = s->PowerMod(key->e, key->n);
        
        // 3. Output m.
        return m;
    }
    
    static int ModularInverse(int a, int n)
    {
        int t = 0; int newt = 1;
        int r = n; int newr = a;
        while (newr != 0) {
            int quotient = r / newr;
            int t2 = newt; int newt2 = t - quotient * newt;
            t = t2; newt = newt2;
            int r2 = newr; int newr2 = r - quotient * newr;
            r = r2; newr = newr2;
        }
        if (r > 1)
            throw "a is not reversible";
        if (t < 0)
            t += n;
        return t;
    }

    KeySet::KeySet(RandomSource *random, int bits)
    {
        LargeNumber *p = new LargeNumber(bits, random, 100);
        LargeNumber *q = new LargeNumber(bits, random, 100);
        LargeNumber *n = p->Multiply(q);
        LargeNumber *one = new LargeNumber(1);
        LargeNumber *p1 = p->Subtract(one);
        LargeNumber *q1 = q->Subtract(one);
        LargeNumber *on = p1->Multiply(q1);
        one->Release();
        LargeNumber *e = new LargeNumber(65537);
        while (true) {
            LargeNumber *rem;
            on->Divide(e, &rem);
            bool good = !rem->IsZero();
            rem->Release();
            if (good)
                break;
            do {
                e->Release();
                e = new LargeNumber(on->Length(), random, 100);
            } while (e->Compare(on) >= 0);
        }
        LargeNumber *d = ModularInverse(e, on);
        publicKey = new Key(n, e);
        privateKey = new Key(n, d);
        e->Release();
        p->Release();
        q->Release();
    }
    
    KeySet::~KeySet()
    {
        privateKey->Release();
        publicKey->Release();
    }
    
    // prefixes
//    MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H.
//    MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H.
//    SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
//    SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
//    SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
//    SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
    
    // 9.2 EMSA-PKCS1-v1_5
    sshBlob* EMSA_PKCS1_V1_5(sshBlob *M, int emLen, HashType *hash)
    {
        // 1. Apply the hash function to the message M to produce a hash value
        //    H:
        //       H = Hash(M).
        //    If the hash function outputs "message too long," output "message
        //    too long" and stop.
        sshBlob *H = hash->Compute(M);
        if (H == NULL)
            return NULL;

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
        sshBlob *T = new sshBlob();
        sshWriter tWriter(T);
        tWriter.Write(hash->EMSA_PKCS1_V1_5_Prefix());
        tWriter.Write(H);
        int tLen = T->Length();

        // 3. If emLen < tLen + 11, output "intended encoded message length too
        //    short" and stop.
        if (emLen < tLen + 11)
            return NULL;

        // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
        //    with hexadecimal value 0xff.  The length of PS will be at least 8
        //    octets.
        int PSlength = emLen - tLen - 3;

        // 5. Concatenate PS, the DER encoding T, and other padding to form the
        //    encoded message EM as
        //       EM = 0x00 || 0x01 || PS || 0x00 || T.
        sshBlob *EM = new sshBlob();
        sshWriter writer(EM);
        writer.Write(Byte(0x00));
        writer.Write(Byte(0x01));
        for (int i = 0; i < PSlength; i++)
            writer.Write(Byte(0xFF));
        writer.Write(Byte(0x00));
        writer.Write(T);

        // 6. Output EM.
        EM->Autorelease();
        return EM;
    }
    
    LargeNumber* OS2IP(sshBlob *blob)
    {
        LargeNumber *result = new LargeNumber(blob->Value(), blob->Length(), false);
        result->Autorelease();
        return result;
    }
    
    sshBlob* I2OSP(LargeNumber *value, int k)
    {
        sshBlob *result = value->Data();
        if (result->Length() < k) {
            // Pad with 0
            sshBlob *newResult = new sshBlob();
            Byte zero = 0;
            int required = k - result->Length();
            for (int i = 0; i < required; i++)
                newResult->Append(&zero, 1);
            newResult->Append(result->Value(), result->Length());
            newResult->Autorelease();
            result = newResult;
        }
        if (result->Length() > k) { // Unlikely this is required anymore
            int remove = result->Length() - k;
            sshBlob *stripped = new sshBlob();
            stripped->Append(result->Value() + remove, result->Length() - remove);
            stripped->Autorelease();
            result = stripped;
        }
        return result;
    }
    
    // 8.2.1 Signature generation operation
    sshBlob *SSA_PKCS1_V1_5::Sign(Key *privateKey, sshBlob *M, HashType *hash)
    {
        int k = (privateKey->n->Length() + 7) / 8;

        // 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
        //    operation (Section 9.2) to the message M to produce an encoded
        //    message EM of length k octets:
        //      EM = EMSA-PKCS1-V1_5-ENCODE (M, k).
        //    If the encoding operation outputs "message too long," output
        //    "message too long" and stop.  If the encoding operation outputs
        //    "intended encoded message length too short," output "RSA modulus
        //    too short" and stop.
        sshBlob *EM = EMSA_PKCS1_V1_5(M, k, hash);
        
        // 2. RSA signature:
        //  a. Convert the encoded message EM to an integer message
        //     representative m (see Section 4.2):
        //       m = OS2IP (EM).
        LargeNumber *m = OS2IP(EM);
        
        //  b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
        //     private key K and the message representative m to produce an
        //     integer signature representative s:
        //       s = RSASP1 (K, m).
        LargeNumber *s = RSASP1(privateKey, m);
        
        //  c. Convert the signature representative s to a signature S of
        //     length k octets (see Section 4.1):
        //       S = I2OSP (s, k).
        sshBlob *S = I2OSP(s, k);
        
        // 3. Output the signature S.
        return S;
    }
    
    // 8.2.2 Signature verification operation
    bool SSA_PKCS1_V1_5::Verify(Key *publicKey, sshBlob *M, sshBlob *S, HashType *hash)
    {
        int k = (publicKey->n->Length() + 7) / 8;
        
        // 1. Length checking: If the length of the signature S is not k octets,
        //    output "invalid signature" and stop.
        if (S->Length() != k)
            return false;
        
        // 2. RSA verification:
        //    a. Convert the signature S to an integer signature representative
        //       s (see Section 4.2):
        //          s = OS2IP (S).
        LargeNumber *s = new LargeNumber(S->Value(), S->Length(), false);
        s->Autorelease();
        
        //    b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
        //       RSA public key (n, e) and the signature representative s to
        //       produce an integer message representative m:
        //          m = RSAVP1 ((n, e), s).
        //       If RSAVP1 outputs "signature representative out of range,"
        //       output "invalid signature" and stop.
        LargeNumber *m = RSAVP1(publicKey, s);
        if (m == NULL)
            return false;
        
        //    c. Convert the message representative m to an encoded message EM
        //       of length k octets (see Section 4.1):
        //          EM = I2OSP (m, k).
        //       If I2OSP outputs "integer too large," output "invalid
        //       signature" and stop.
        sshBlob *EM = m->Data();
        if (EM->Length() < k) {
            // Pad with 0
            sshBlob *newEM = new sshBlob();
            Byte zero = 0;
            int required = k - EM->Length();
            for (int i = 0; i < required; i++)
                newEM->Append(&zero, 1);
            newEM->Append(EM->Value(), EM->Length());
            newEM->Autorelease();
            EM = newEM;
        }
        if (EM->Length() > k) { // Unlikely this is required anymore
            int remove = EM->Length() - k;
            sshBlob *stripped = new sshBlob();
            stripped->Append(EM->Value() + remove, EM->Length() - remove);
            stripped->Autorelease();
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
        sshBlob *EM_ = EMSA_PKCS1_V1_5(M, k, hash);
        
        // 4. Compare the encoded message EM and the second encoded message EM'.
        //    If they are the same, output "valid signature"; otherwise, output
        //    "invalid signature."
        return EM->Compare(EM_);
    }
}
