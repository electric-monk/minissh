//
//  Maths.cpp
//  minissh
//
//  Created by Colin David Munro on 18/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "Maths.h"

static int Max(int a, int b)
{
    return (a > b) ? a : b;
}

LargeNumber::LargeNumber(int bits, RandomSource *source, int primeCertainty)
{
    _positive = true;
    _count = (bits + (sizeof(DigitType) * 8) - 1) / (8 * sizeof(DigitType));
    _digits = new DigitType[_count];
    while (true) {
        for (int i = 0; i < _count; i++)
            _digits[i] = source->Random();
        _digits[bits / sizeof(DigitType)] |= 1 << (bits % sizeof(DigitType));
        if (IsProbablePrime(primeCertainty)) {
            break;
        }
    }
}

LargeNumber::LargeNumber(LargeNumber *original)
{
    _positive = original->_positive;
    _count = original->_count;
    _digits = new DigitType[_count];
    memcpy(_digits, original->_digits, sizeof(DigitType) * _count);
}

LargeNumber::LargeNumber(int value)
{
    if (value < 0) {
        value = -value;
        _positive = false;
    } else {
        _positive = true;
    }
    _count = (sizeof(value) + (sizeof(DigitType) - 1)) / sizeof(DigitType);
    _digits = new DigitType[_count];
    _digits[_count - 1] = 0;
    const Byte *input = (Byte*)&value;
    Byte *output = (Byte*)_digits;
    for (int i = 0; i < sizeof(value); i++)
        output[i] = input[i];
    Compact();
}

LargeNumber::LargeNumber(const UInt32 *data, int count, bool reverse)
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

LargeNumber::LargeNumber(const void *bytes, int count, bool checkSign)
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

sshBlob* LargeNumber::Data(void)
{
    sshBlob *result = new sshBlob();
    if (_positive) {
        result->Append((Byte*)_digits, sizeof(DigitType) * _count);
        if (_digits[_count - 1] & ((UInt64(1) << ((sizeof(DigitType) * 8) - 1)))) {
            Byte zero = 0;
            result->Append(&zero, sizeof(zero));
        }
    } else {
        UInt32 carry = 1;
        for (int i = 0; i < _count * sizeof(DigitType); i++) {
            Byte value = ~((Byte*)_digits)[i];
            UInt32 total = UInt32(value) + carry;
            value = Byte(total);
            carry = total >> 8;
            result->Append(&value, 1);
        }
        if (carry) {
            // Since we're only adding 1, this can only be 1, which means "fill it up with bits" for Two's complement. If carry started as anything other than 1 we'd need to be slightly cleverer
            Byte v = 0xFF;
            result->Append(&v, 1);
        }
    }
    // The caller wants MSB first
    sshBlob *resultReversed = new sshBlob();
    for (int i = result->Length(); i != 0; i--)
        resultReversed->Append(result->Value() + i - 1, 1);
    // Fix invalid padding
    int strip = 0;
    int max = resultReversed->Length() - 1;
    if (_positive) {
        while (strip < max) {
            const Byte *current = resultReversed->Value();
            if (current[strip] != 0)
                break;
            if (current[strip + 1] & 0x80)
                break;
            strip++;
        }
    } else {
        while (strip < max) {
            const Byte *current = resultReversed->Value();
            if (current[strip] != 0xFF)
                break;
            if (!(current[strip + 1] & 0x80))
                break;
            strip++;
        }
    }
    resultReversed->Strip(0, strip);
    // Done
    result->Release();
    resultReversed->Autorelease();
    return resultReversed;
}

LargeNumber::LargeNumber(int capacity, bool clear)
{
    _positive = true;
    _count = capacity;
    _digits = new DigitType[_count];
    if (clear)
        memset(_digits, 0, sizeof(DigitType) * _count);
}

LargeNumber::~LargeNumber()
{
    delete[] _digits;
}

const char *_HEX = "0123456789ABCDEF";

void LargeNumber::Print(FILE *f)
{
    putc(_positive ? '+' : '-', f);
    for (int i = _count; i > 0; i--) {
        DigitType digit = _digits[i - 1];
        for (int j = sizeof(DigitType); j != 0; j--) {
            DigitType value = digit >> ((j - 1) * 8);
            UInt32 high = (value & 0xF0) >> 4;
            UInt32 low = value & 0x0F;
            putc(_HEX[high], f);
            putc(_HEX[low], f);
        }
    }
    printf("\n");
}

void LargeNumber::Compact(void)
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

void LargeNumber::CheckSign(void)
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

LargeNumber* LargeNumber::Add(LargeNumber *other)
{
    // a + b = a+b
    // -a + b = b-abs(a)
    // a + -b = a-abs(b)
    // -a + -b = -(abs(a)+abs(b))
    if (_positive == other->_positive) {
        LargeNumber *result = _Add(other);
        if (!_positive)
            result->_positive = false;
        return result;
    }
    if (!_positive)
        return other->_Subtract(this);
    else
        return _Subtract(other);
}

LargeNumber* LargeNumber::Subtract(LargeNumber *other)
{
    // a - b = a-b
    // a - (-b) = a+abs(b)
    // (-a) - b = -(abs(a)+b)
    // (-a) - (-b) = (abs(b) - abs(a))
    if (_positive == other->_positive) {
        if (_positive)
            return _Subtract(other);
        else
            return other->_Subtract(this);
    }
    LargeNumber *result = _Add(other);
    if (!_positive)
        result->_positive = false;
    return result;
}

LargeNumber* LargeNumber::Multiply(LargeNumber *other)
{
    // a * b = a*b
    // a * (-b) = -(a*b)
    // (-a) * b = -(a*b)
    // (-a) * (-b) = a*b
    LargeNumber *result = _Multiply(other);
    if (_positive != other->_positive)
        result->_positive = false;
    return result;
}

LargeNumber* LargeNumber::Divide(LargeNumber *number, LargeNumber **remainder)
{
    // a / b = a/b
    // a / (-b) = -(a/b)
    // (-a) / b = -(a/b)
    // (-a) / (-b) = a/b
    LargeNumber *result = _Divide(number, remainder);
    if (remainder && *remainder)
        (*remainder)->_positive = _positive;
    if (_positive != number->_positive)
        result->_positive = false;
    return result;
}

LargeNumber* LargeNumber::_Add(LargeNumber *other)
{
    // First, find maximum number of digits
    int n = Max(_count, other->_count);
    LargeNumber *result = new LargeNumber(n + 1, false);
    result->Autorelease();
    // Run algorithm
    UInt64 k = 0; // carry
    for (int j = 0; j < n; j++) {
        UInt64 sum = UInt64((j < _count) ? _digits[j] : 0) + UInt64((j < other->_count) ? other->_digits[j] : 0) + UInt64(k);
        result->_digits[j] = DigitType(sum & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
        k = sum >> (sizeof(DigitType) * 8);
    }
    result->_digits[n] = DigitType(k);
    result->Compact();
    return result;
}

LargeNumber* LargeNumber::_Subtract(LargeNumber *other)
{
    // First, find maximum number of digits
    int n = Max(_count, other->_count);
    LargeNumber *result = new LargeNumber(n + 1, false);
    result->Autorelease();
    // Run algorithm
    UInt64 k = 0; // carry
    for (int j = 0; j < n; j++) {
        UInt64 sum = UInt64((j < _count) ? _digits[j] : 0) - UInt64((j < other->_count) ? other->_digits[j] : 0) + UInt64(k);
        result->_digits[j] = DigitType(sum & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
        k = sum >> (sizeof(DigitType) * 8);
    }
    result->_digits[n] = DigitType(k);
    result->CheckSign();
    return result;
}

LargeNumber* LargeNumber::_Multiply(LargeNumber *other)
{
    int m = _count, n = other->_count;
    LargeNumber *result = new LargeNumber(m + n, true);
    result->Autorelease();
    for (int j = 0; j < n; j++) {
        DigitType k = 0;
        for (int i = 0; i < m; i++) {
            UInt64 t = UInt64(_digits[i]) * UInt64(other->_digits[j]) + result->_digits[i + j] + k;
            result->_digits[i + j] = DigitType(t & ((UInt64(1) << (sizeof(DigitType) * 8)) - 1));
            k = t >> (sizeof(DigitType) * 8);
        }
        result->_digits[j + m] = k;
    }
    result->Compact();
    result->_positive = _positive == other->_positive;
    return result;
}

static int nlz(unsigned x)
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

LargeNumber* LargeNumber::_Divide(LargeNumber *other, LargeNumber **remainder)
{
    // Based on http://www.hackersdelight.org/hdcodetxt/divmnu.c.txt
    
    const UInt32 bs = sizeof(DigitType) * 8;
    const UInt64 b = UInt64(1) << bs;
    
    // Parameters
    if (other == NULL)
        return NULL;
    UInt32 m = _count;
    UInt32 n = other->_count;
    const DigitType *u = _digits;
    const DigitType *v = other->_digits;
    
    // Validate parameters
    if (remainder)
        *remainder = NULL;
    if ((n == 0) || (v[n - 1] == 0))
        return NULL;
    if (m < n) {
        if (remainder)
            *remainder = new LargeNumber(this);
        LargeNumber *result = new LargeNumber(0);
        result->Autorelease();
        return result;
    }

    // Allocate output values
    LargeNumber *result = new LargeNumber(m - n + 1, true);
    DigitType *q = result->_digits;
    DigitType *r = NULL;
    if (remainder) {
        *remainder = new LargeNumber(n, true);
        r = (*remainder)->_digits;
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
            (*remainder)->Compact();
        }
        result->Compact();
        result->Autorelease();
        return result;
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
        (*remainder)->Compact();
    }
    
    delete[] vn;
    delete[] un;
    result->Compact();
    result->Autorelease();
    return result;
}

bool LargeNumber::IsZero(void)
{
    for (int i = 0; i < _count; i++) {
        if (_digits[i] != 0)
            return false;
    }
    return true;
}

int LargeNumber::Compare(LargeNumber *other)
{
    if (_positive && !other->_positive)
        return -1;
    if (!_positive && other->_positive)
        return 1;
    if (_count == other->_count) {
        for (int i = _count; i > 0; i--) {
            int j = i - 1;
            if (_digits[j] > other->_digits[j])
                return _positive ? -1 : 1;
            if (_digits[j] < other->_digits[j])
                return _positive ? 1 : -1;
        }
        return 0;
    } else {
        return (_count > other->_count) ? -1 : 1;
    }
}

LargeNumber* LargeNumber::PowerMod(LargeNumber *power, LargeNumber *mod)
{
    if (!mod->_positive || mod->IsZero())
        return NULL;
    if (!power->_positive)  // TODO?
        return NULL;
    LargeNumber *one = new LargeNumber(1);
    if (power->Compare(one) == 0) {
        one->Release();
        Divide(mod, &one);
        one->Autorelease();
        return one;
    }
    LargeNumber *s = one;
    {
        Releaser releaser;
        LargeNumber *u = power;
        LargeNumber *t = this;
        while (!u->IsZero()) {
            if (!u->And(one)->IsZero()) {
                LargeNumber *rem;
                LargeNumber *big = s->Multiply(t);
                big->Divide(mod, &rem);
                rem->Autorelease();
                s = rem;
            }
            u = u->ShiftRight(1);
            LargeNumber *rem;
            LargeNumber *big = t->Multiply(t);
            big->Divide(mod, &rem);
            rem->Autorelease();
            t = rem;
            // temp
            u->AddRef();
            t->AddRef();
            s->AddRef();
            releaser.Flush();
            u->Autorelease();
            t->Autorelease();
            s->Autorelease();
        }
        s->AddRef();
    }
    one->Release();
    s->Autorelease();
    return s;
}

LargeNumber* LargeNumber::And(LargeNumber *other)
{
    int count = (_count > other->_count) ? other->_count : _count;
    LargeNumber *result = new LargeNumber(count, false);
    for (int i = 0; i < count; i++)
        result->_digits[i] = _digits[i] & other->_digits[i];
    result->Compact();
    result->Autorelease();
    return result;
}

LargeNumber* LargeNumber::ShiftRight(UInt32 amount) // Currently, max is sizeof(DigitType) * 8
{
    LargeNumber *result = new LargeNumber(this);
    DigitType saved = 0;
    for (int i = result->_count; i != 0; i--) {
        DigitType value = result->_digits[i - 1];
        DigitType nextSaved = value & ((1 << (amount + 1)) - 1);
        result->_digits[i - 1] = (value >> amount) | (saved << ((sizeof(DigitType) * 8) - amount));
        saved = nextSaved;
    }
    result->Compact();
    result->Autorelease();
    return result;
}

const UInt32 k[] = {100,150,200,250,300,350,400,500,600,800,1250, 0xFFFFFFFF};
const UInt32 t[] = { 27, 18, 15, 12,  9,  8,  7,  6,  5,  4,   3, 2};
const UInt32 primes[] = {    2,   3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
                            47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107,
                           109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
                           191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251 };

bool LargeNumber::IsProbablePrime(int certainty)
{
    Releaser releaser;
    int i;
    
    if (certainty < 1)
        return true;
    for (i = 0; i < (sizeof(primes) / sizeof(primes[0])); i++) {
        LargeNumber *temp = new LargeNumber(primes[i]);
        temp->Autorelease();
        if (Compare(temp) == 0)
            return true;
        LargeNumber *rem;
        _Divide(temp, &rem);
        rem->Autorelease();
        if (rem->IsZero()) {
            return false;
        }
    }
    LargeNumber *one = new LargeNumber(1);
    one->Autorelease();
    LargeNumber *two = new LargeNumber(2);
    two->Autorelease();
    LargeNumber *pMinus1 = Subtract(one);
    int b = pMinus1->GetLowestSetBit();
    LargeNumber *dividing = new LargeNumber(1 << b);
    LargeNumber *m = pMinus1->Divide(dividing, NULL);
    dividing->Release();
    int bits = Length();
    for (i = 0; i < (sizeof(k) / sizeof(k[0])); i++)
        if (bits <= k[i])
            break;
    int trials = t[i];
    if (certainty > 80)
        trials *= 2;
    for (int t = 0; t < trials; t++) {
        LargeNumber *z0 = new LargeNumber(primes[t]);
        LargeNumber *z = z0->PowerMod(m, this);
        z0->Release();
        if ((z->Compare(one) == 0) || (z->Compare(pMinus1) == 0))
            continue;
        for (i = 1; i < b;) {
            if (z->Compare(one) == 0) {
                return false;
            }
            i++;
            if (z->Compare(pMinus1) == 0)
                break;
            z = z->PowerMod(two, this);
        }
        if ((i == b) && (z->Compare(pMinus1) != 0)) {
            return false;
        }
    }
    return true;
}

int LargeNumber::GetLowestSetBit(void)
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

int LargeNumber::Length(void)
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

bool LargeNumber::IsBitSet(int bit)
{
    int index = bit / sizeof(DigitType);
    if (index >= _count)
        return false;
    return _digits[index] & (1 << (bit % sizeof(DigitType)));
}
