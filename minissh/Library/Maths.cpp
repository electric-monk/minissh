//
//  Maths.cpp
//  minissh
//
//  Created by Colin David Munro on 18/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "Maths.h"
#include "Types.h"

namespace minissh::Maths {

namespace {
    
BigNumber EuclideanGCD(const BigNumber& a, const BigNumber& b, BigNumber& x, BigNumber& y)
{
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    BigNumber x1, y1;
    BigNumber gcd = EuclideanGCD(b % a, a, x1, y1);
    x = y1 - (b / a ) * x1;
    y = x1;
    return gcd;
}

int nlz(unsigned x)
{
    int n;
    
    if (x == 0) return(32);
    n = 0;
    if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
    if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
    if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
    if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
    if (x <= 0x7FFFFFFF) {n = n + 1;}
    return n;
}

}
    
BigNumber::BigNumber()
{
    _count = 1;
    _digits = new DigitType[1];
    _positive = true;
    _digits[0] = 0;
}

BigNumber::BigNumber(const BigNumber &original)
{
    _count = original._count;
    _digits = new DigitType[_count];
    memcpy(_digits, original._digits, _count * sizeof(DigitType));
    _positive = original._positive;
}

BigNumber::BigNumber(int simpleValue)
{
    if (simpleValue < 0) {
        simpleValue = -simpleValue;
        _positive = false;
    } else {
        _positive = true;
    }
    _count = (sizeof(simpleValue) + (sizeof(DigitType) - 1)) / sizeof(DigitType);
    _digits = new DigitType[_count];
    _digits[_count - 1] = 0;
    const Byte *input = (Byte*)&simpleValue;
    Byte *output = (Byte*)_digits;
    for (int i = 0; i < sizeof(simpleValue); i++)
        output[i] = input[i];
    Compact();
}

BigNumber::BigNumber(const void *bytes, UInt32 count, bool checkSign)
{
    _count = (count + (sizeof(DigitType) - 1)) / sizeof(DigitType);
    _digits = new DigitType[_count + 1];
    // _digits is LSB first, bytes is MSB first. bytes is 2's complement, _digits is not.
    Byte *output = (Byte*)_digits;
    const Byte *input = (Byte*)bytes;
    // Copy straight (TODO: some endianness issue here)
    int i = 0;
    for (i = 0; i < count; i++)
        output[i] = input[count - (i + 1)];
    _count++;   // Since we added one to the "new"
    unsigned char extension = (checkSign && (((Byte*)bytes)[0] & 0x80)) ? 0xFF: 0x00;
    while (i < (_count * sizeof(DigitType))) {
        output[i] = extension;
        i++;
    }
    _positive = true;
    CheckSign();
}

BigNumber::BigNumber(const UInt32 *data, UInt32 count, bool reverse)
{
    _count = count;
    _positive = true;
    _digits = new DigitType[_count];
    if (reverse) {
        for (int i = 0; i < count; i++)
            _digits[count - (i + 1)] = data[i];
    } else {
        memcpy(_digits, data, count * sizeof(DigitType));
    }
    Compact();
}

BigNumber::BigNumber(UInt32 bits, RandomSource &source, int primeCertainty)
{
    _positive = true;
    _count = (bits + (sizeof(DigitType) * 8) - 1) / (8 * sizeof(DigitType));
    _digits = new DigitType[_count];
    while (true) {
        for (int i = 0; i < _count; i++)
            _digits[i] = source.Random();
        _digits[bits / sizeof(DigitType)] |= 1 << (bits % sizeof(DigitType));
        if (IsProbablePrime(primeCertainty)) {
            break;
        }
    }
}

BigNumber::~BigNumber()
{
    delete[] _digits;
}

int BigNumber::Compare(const BigNumber &other) const
{
    if (_positive && !other._positive)
        return -1;
    if (!_positive && other._positive)
        return 1;
    if (_count == other._count) {
        for (int i = _count; i > 0; i--) {
            int j = i - 1;
            if (_digits[j] > other._digits[j])
                return _positive ? -1 : 1;
            if (_digits[j] < other._digits[j])
                return _positive ? 1 : -1;
        }
        return 0;
    } else {
        return (_count > other._count) ? -1 : 1;
    }
}

void BigNumber::Expand(UInt32 size)
{
    if (_count >= size)
        return;
    DigitType *other = new DigitType[size];
    memcpy(other, _digits, sizeof(DigitType) * _count);
    memset(other + _count, 0, sizeof(DigitType) * (size - _count));
    _count = size;
    delete[] _digits;
    _digits = other;
}

void BigNumber::Compact(void)
{
    UInt32 pos;
    for (pos = _count - 1; (_digits[pos] == 0) && (pos != 0); pos--);
    pos++;
    if (pos == _count)
        return;
    DigitType *other = new DigitType[pos];
    memcpy(other, _digits, sizeof(DigitType) * pos);
    delete[] _digits;
    _digits = other;
    _count = pos;
}

void BigNumber::CheckSign(void)
{
    if (_digits[_count - 1] & (1 << ((sizeof(DigitType) * 8) - 1))) {
        // Two's complement - invert
        for (int i = 0; i < _count; i++)
            _digits[i] = ~_digits[i];
        // Add an extra digit
        DigitType *moreBytes = new DigitType[_count + 1];
        memcpy(moreBytes, _digits, _count * sizeof(DigitType));
        delete[] _digits;
        _digits = moreBytes;
        // Two's complement - add one
        UInt64 carry = 1;
        for (int i = 0; i < _count; i++) {
            UInt64 chunk = UInt64(_digits[i]) + carry;
            _digits[i] = chunk & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1);
            carry = chunk >> (sizeof(DigitType) * 8);
        }
        // Finish off
        _digits[_count] = DigitType(carry);
        _count++;
        _positive = !_positive;
    }
    Compact();
}

bool BigNumber::operator[](UInt32 bit) const
{
    int index = bit / sizeof(DigitType);
    if (index >= _count)
        return false;
    return _digits[index] & (1 << (bit % sizeof(DigitType)));
}

BigNumber& BigNumber::operator&=(const BigNumber &rightSide)
{
    int count = (_count > rightSide._count) ? rightSide._count : _count;
    for (int i = 0; i < count; i++)
        _digits[i] &= rightSide._digits[i];
    for (int i = count; i < _count; i++)
        _digits[i] = 0;
    Compact();
    return *this;
}

BigNumber& BigNumber::operator|=(const BigNumber &rightSide)
{
    int count = (_count > rightSide._count) ? rightSide._count : _count;
    for (int i = 0; i < count; i++)
        _digits[i] |= rightSide._digits[i];
    Compact();
    return *this;
}

BigNumber& BigNumber::operator^=(const BigNumber &rightSide)
{
    int count = (_count > rightSide._count) ? rightSide._count : _count;
    for (int i = 0; i < count; i++)
        _digits[i] ^= rightSide._digits[i];
    Compact();
    return *this;
}

// TODO: Optimise shifting methods, as they can very easily shift in multiples of sizeof(DigitType) before the last step of sub-size shifting

BigNumber& BigNumber::operator>>=(const BigNumber &rightSide)
{
    BigNumber remains = rightSide;
    while (remains != 0) {
        int amount = sizeof(DigitType) * 8;
        if (BigNumber(amount) > remains)
            amount = remains.AsInt();
        DigitType saved = 0;
        for (int i = _count; i != 0; i--) {
            DigitType value = _digits[i - 1];
            DigitType nextSaved = value & ((1 << (amount + 1)) - 1);
            _digits[i - 1] = (value >> amount) | (saved << ((sizeof(DigitType) * 8) - amount));
            saved = nextSaved;
        }
        remains -= amount;
    }
    Compact();
    return *this;
}

BigNumber& BigNumber::operator<<=(const BigNumber &rightSide)
{
    BigNumber remains = rightSide;
    
    BigNumber extraCount = (remains + (sizeof(DigitType) * 8) - 1) / sizeof(DigitType);
    Expand(_count + extraCount.AsInt());
    
    while (remains != 0) {
        int amount = sizeof(DigitType) * 8;
        if (BigNumber(amount) > remains)
            amount = remains.AsInt();
        DigitType saved = 0;
        for (int i = 0; i != _count; i++) {
            DigitType value = _digits[i];
            DigitType nextSaved = value & (((1 << amount) - 1) << (sizeof(DigitType) - amount));
            _digits[i] = (value << amount) | (saved >> (sizeof(DigitType) - amount));
            saved = nextSaved;
        }
        remains -= amount;
    }
    Compact();
    return *this;
}

BigNumber BigNumber::operator~()
{
    BigNumber result = *this;
    for (int i = 0; i < result._count; i++)
        result._digits[i] = ~_digits[i];
    return result;
}

void BigNumber::Add(const BigNumber &other)
{
    UInt32 n = std::max(_count, other._count);
    Expand(n + 1);
    UInt64 k = 0; // Carry
    for (UInt32 j = 0; j < n; j++) {
        UInt64 sum = UInt64((j < _count) ? _digits[j] : 0) + UInt64((j < other._count) ? other._digits[j] : 0) + k;
        _digits[j] = DigitType(sum & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
        k = sum >> (sizeof(DigitType) * 8);
    }
    _digits[n] = DigitType(k);
    Compact();
}

void BigNumber::Subtract(const BigNumber &other)
{
    UInt32 n = std::max(_count, other._count);
    Expand(n + 1);
    UInt64 k = 0; // Carry
    for (UInt32 j = 0; j < n; j++) {
        UInt64 sum = UInt64((j < _count) ? _digits[j] : 0) - UInt64((j < other._count) ? other._digits[j] : 0) + k;
        _digits[j] = DigitType(sum & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
        k = sum >> (sizeof(DigitType) * 8);
    }
    _digits[n] = DigitType(k);
    CheckSign();
}

void BigNumber::Multiply(const BigNumber &other)
{
    UInt32 m = _count, n = other._count;
    DigitType *result = new DigitType[m + n];
    memset(result, 0, sizeof(DigitType) * (m + n));
    for (int j = 0; j < n; j++) {
        DigitType k = 0;
        for (int i = 0; i < m; i++) {
            UInt64 t = UInt64(_digits[i]) * UInt64(other._digits[j]) + result[i + j] + k;
            result[i + j] = DigitType(t & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
            k = t >> (sizeof(DigitType) * 8);
        }
        result[j + m] = k;
    }
    _count = m + n;
    delete[] _digits;
    _digits = result;
    Compact();
    _positive = _positive == other._positive;
}

void BigNumber::_Divide(const BigNumber &other, BigNumber *remainder)
{
    // Based on http://www.hackersdelight.org/hdcodetxt/divmnu.c.txt
    
    const UInt32 bs = sizeof(DigitType) * 8;
    const UInt64 b = UInt64(1) << bs;
    
    // Parameters
    UInt32 m = _count;
    UInt32 n = other._count;
    const DigitType *u = _digits;
    const DigitType *v = other._digits;
    
    // Validate parameters
    if ((n == 0) || (v[n - 1] == 0))
        throw "Error";
    if (m < n) {
        if (remainder)
            *remainder = *this;
        *this = 0;
        return;
    }
    
    // Allocate output values
    DigitType *q = new DigitType[m - n + 1];
    DigitType *r = NULL;
    memset(q, 0, sizeof(DigitType) * (m - n + 1));
    if (remainder) {
        r = new DigitType[n];
        memset(r, 0, sizeof(DigitType) * n);
        
        delete[] remainder->_digits;
        remainder->_digits = r;
        remainder->_count = n;
    }
    
    // Take care of single digit divisor here
    if (n == 1) {
        UInt64 k = 0;
        for (int j = m - 1; j >= 0; j--) {
            UInt64 t = k * b + u[j];
            q[j] = (DigitType)(t / v[0]);
            k = t - q[j] * v[0];
        }
        if (r != NULL) {
            r[0] = (DigitType)k;
            remainder->Compact();
        }
        delete[] _digits;
        _digits = q;
        _count = m - n + 1;
        Compact();
        return;
    }
    
    // Normalize by shifting v left just enough so that
    // its high-order bit is on, and shift u left the
    // same amount.  We may have to append a high-order
    // digit on the dividend; we do that unconditionally.
    
    UInt32 s = nlz(v[n - 1]);
    // shift v
    DigitType *vn = new DigitType[n];
    for (UInt32 i = n - 1; i != 0; i--)
        vn[i] = UInt32((UInt64(v[i]) << s) | (UInt64(v[i - 1]) >> (bs - s)));
    vn[0] = v[0] << s;
    // shift u
    DigitType *un = new DigitType[m + 1];
    un[m] = UInt32(UInt64(u[m - 1]) >> (bs - s));
    for (UInt32 i = m - 1; i != 0; i--)
        un[i] = UInt32((UInt64(u[i]) << s) | (UInt64(u[i - 1]) >> (bs - s)));
    un[0] = u[0] << s;
    
    for (int j = m - n; j >= 0; j--) {
        // Compute estimate
        UInt64 temp = un[j + n] * b + un[j + n - 1];
        DigitType vnn1 = vn[n - 1];
        UInt64 qhat = temp / vnn1;
        UInt64 rhat = temp - qhat * vnn1;
    again:
        if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2]) {
            qhat -= 1;
            rhat += vnn1;
            if (rhat < b)
                goto again;
        }
        
        // Multiply and subtract
        signed long long k = 0;
        signed long long t = 0;
        for (UInt32 i = 0; i < n; i++) {
            UInt64 p = qhat * vn[i];
            t = un[i + j] - k - (p & (b - 1));
            un[i + j] = (UInt32)t;
            k = (p >> bs) - (t >> bs);
        }
        t = un[j + n] - k;
        un[j + n] = (DigitType)t;
        
        q[j] = (DigitType)qhat;
        if (t < 0) {
            q[j] -= 1;
            k = 0;
            for (UInt32 i = 0; i < n; i++) {
                t = UInt64(un[i + j]) + UInt64(vn[i]) + k;
                un[i + j] = (DigitType)t;
                k = t >> bs;
            }
            un[j + n] += k;
        }
    }
    
    if (r != NULL) {
        for (UInt32 i = 0; i < n - 1; i++)
            r[i] = DigitType((un[i] >> s) | (UInt64(un[i + 1]) << (bs - s)));
        r[n - 1] = DigitType(un[n - 1] >> s);
        remainder->Compact();
    }
    
    delete[] vn;
    delete[] un;
    delete[] _digits;
    _digits = q;
    _count = m - n + 1;
    Compact();
}

BigNumber BigNumber::PowerMod(const BigNumber &pow, const BigNumber &mod) const
{
    if (!mod._positive || (mod == 0))
        throw "Error";
    if (!pow._positive)
        throw "TODO";
    if (pow == 1)
        return *this % mod;
    BigNumber s = 1;
    BigNumber u = pow;
    BigNumber t = *this;
    while (u != 0) {
        if ((u & 1) != 0)
            (s * t)._Divide(mod, &s);
        u >>= 1;
        (t * t)._Divide(mod, &t);
    }
    return s;
}

const UInt32 k[] = {100,150,200,250,300,350,400,500,600,800,1250, 0xFFFFFFFF};
const UInt32 t[] = { 27, 18, 15, 12,  9,  8,  7,  6,  5,  4,   3, 2};
const UInt32 primes[] = {    2,   3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
                            47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107,
                           109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
                           191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251 };

bool BigNumber::IsProbablePrime(int certainty)
{
    int i;
    
    if (certainty < 1)
        return true;
    for (i = 0; i < (sizeof(primes) / sizeof(primes[0])); i++) {
        if (*this == primes[i])
            return true;
        BigNumber rem;
        _Divide(primes[i], &rem);
        if (rem == 0)
            return false;
    }
    BigNumber pMinus1 = *this - 1;
    int b = pMinus1.GetLowestSetBit();
    BigNumber m = pMinus1 / (1 << b);
    int bits = BitLength();
    for (i = 0; i < (sizeof(k) / sizeof(k[0])); i++)
        if (bits <= k[i])
            break;
    int trials = t[i];
    if (certainty > 80)
        trials *= 2;
    for (int t = 0; t < trials; t++) {
        BigNumber z = BigNumber(primes[t]).PowerMod(m, *this);
        if ((z == 1) || (z == pMinus1))
            continue;
        for (i = 1; i < b;) {
            if (z == 1)
                return false;
            i++;
            if (z == pMinus1)
                break;
            z = z.PowerMod(2, *this);
        }
        if ((i == b) && (z == pMinus1))
            return false;
    }
    return true;
}

int BigNumber::GetLowestSetBit(void)
{
    for (int i = 0; i < _count; i++) {
        for (int j = 0; j < (sizeof(DigitType) * 8); j++) {
            if (_digits[i] & (1 << j)) {
                return (i * sizeof(DigitType) * 8) + j;
            }
        }
    }
    return -1;
}

int BigNumber::BitLength(void) const
{
    // We should always have been compacted, so we can use that knowledge here
    DigitType lastDigit = _digits[_count - 1];
    int i = 0;
    while (lastDigit) {
        i++;
        lastDigit >>= 1;
    }
    int sizeofEntry = sizeof(DigitType) * 8;
    return (_count * sizeofEntry) - (sizeofEntry - i) - (_positive ? 0 : 1);
}

int BigNumber::AsInt(void)
{
    if (_count > 1)
        throw "Error";
    if (_positive)
        return _digits[0];
    else
        return -_digits[0];
}

Types::Blob BigNumber::Data(void) const
{
    Types::Blob result;
    if (_positive) {
        result.Append((Byte*)_digits, sizeof(DigitType) * _count);
        if (_digits[_count - 1] & ((UInt64(1) << ((sizeof(DigitType) * 8) - 1)))) {
            Byte zero = 0;
            result.Append(&zero, sizeof(zero));
        }
    } else {
        UInt32 carry = 1;
        for (int i = 0; i < _count * sizeof(DigitType); i++) {
            Byte value = ~((Byte*)_digits)[i];
            UInt32 total = UInt32(value) + carry;
            value = Byte(total);
            carry = total >> 8;
            result.Append(&value, 1);
        }
        if (carry) {
            // Since we're only adding 1, this can only be 1, which means "fill it up with bits" for Two's complement. If carry started as anything other than 1 we'd need to be slightly cleverer
            Byte v = 0xFF;
            result.Append(&v, 1);
        }
    }
    // The caller wants MSB first
    Types::Blob resultReversed;
    for (int i = result.Length(); i != 0; i--)
        resultReversed.Append(result.Value() + i - 1, 1);
    // Fix invalid padding
    int strip = 0;
    int max = resultReversed.Length() - 1;
    if (_positive) {
        while (strip < max) {
            const Byte *current = resultReversed.Value();
            if (current[strip] != 0)
                break;
            if (current[strip + 1] & 0x80)
                break;
            strip++;
        }
    } else {
        while (strip < max) {
            const Byte *current = resultReversed.Value();
            if (current[strip] != 0xFF)
                break;
            if (!(current[strip + 1] & 0x80))
                break;
            strip++;
        }
    }
    resultReversed.Strip(0, strip);
    // Done
    return resultReversed;
}

std::string BigNumber::ToString(void) const
{
    static const char *_HEX = "0123456789ABCDEF";
    std::string result;
    
    result.append(_positive ? "+" : "-");
    for (int i = _count; i > 0; i--) {
        DigitType digit = _digits[i - 1];
        for (int j = sizeof(DigitType); j != 0; j--) {
            DigitType value = digit >> ((j - 1) * 8);
            UInt32 high = (value & 0xF0) >> 4;
            UInt32 low = value & 0x0F;
            result.append(_HEX + high, 1);
            result.append(_HEX + low, 1);
        }
    }
    return result;
}

BigNumber BigNumber::ModularInverse(const BigNumber& m)
{
    BigNumber x, y;
    if (EuclideanGCD(*this, m, x, y) != 1)
        throw std::runtime_error("Not reversible");
    else
        return (x % m + m) % m;
}

    
} // namespace minissh::Maths
