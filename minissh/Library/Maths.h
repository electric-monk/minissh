//
//  Maths.h
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef minissh_Maths_h
#define minissh_Maths_h

#include <stdio.h>
#include "Types.h"

// TODO: A nice, operator overriding class, not involving the heap

class RandomSource
{
public:
    virtual ~RandomSource(){}
    virtual UInt32 Random(void) = 0;
};

class LargeNumber : public sshObject
{
public:
    LargeNumber(LargeNumber *original);
    LargeNumber(int value);
    LargeNumber(const void *bytes, int count, bool checkSign = true);
    LargeNumber(const UInt32 *data, int count, bool reverse = false);
    LargeNumber(int capacity, bool clear);
    LargeNumber(int bits, RandomSource *source, int primeCertainty);
    
    void Print(FILE *f);
    sshBlob* Data(void);

    LargeNumber* Add(LargeNumber *other);
    LargeNumber* Subtract(LargeNumber *other);
    LargeNumber* Multiply(LargeNumber *other);
    LargeNumber* Divide(LargeNumber *other, LargeNumber **remainder);
    LargeNumber* PowerMod(LargeNumber *power, LargeNumber *mod);
    LargeNumber* And(LargeNumber *other);   // Bitwise AND
    LargeNumber* ShiftRight(UInt32 shift);  // Bitwise shift
    
    bool IsZero(void);
    bool IsProbablePrime(int certainty);
    int GetLowestSetBit(void);
    int Length(void);
    bool IsBitSet(int bit);
    int Compare(LargeNumber *other);

protected:
    ~LargeNumber();
    
private:
    typedef UInt32 DigitType;
    
    LargeNumber* _Add(LargeNumber *other);
    LargeNumber* _Subtract(LargeNumber *other);
    LargeNumber* _Multiply(LargeNumber *other);
    LargeNumber* _Divide(LargeNumber *other, LargeNumber **remainder);
    void Compact(void);
    void CheckSign(void);
    
    bool _positive;
    DigitType *_digits;
    UInt32 _count;
};

#if 0
class BigNumber
{
private:
    typedef UInt32 DigitType;
    
    bool _positive;
    DigitType *_digits;
    UInt32 _count;
    
    void Compact(void)
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
public:
    BigNumber(int value)
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
    
    BigNumber(const BigNumber &toCopy)
    {
        _positive = toCopy._positive;
        _count = toCopy._count;
        _digits = new DigitType[_count];
        memcpy(_digits, toCopy._digits, sizeof(DigitType) * _count);
    }
    
    ~BigNumber()
    {
        delete[] _digits;
    }
    
    BigNumber& operator=(const BigNumber &value)
    {
        delete[] _digits;
        _positive = value._positive;
        _count = value._count;
        _digits = new DigitType[_count];
        memcpy(_digits, value._digits, sizeof(DigitType) * _count);
        return *this;
    }
    
    BigNumber& operator+=(const BigNumber &rhs)
    {
        
    }
    
    const BigNumber operator+(const BigNumber &other) const
    {
        return BigNumber(*this) += other;
    }
};
#endif

#endif /* defined(minissh_Maths_h) */
