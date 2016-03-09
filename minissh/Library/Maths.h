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
#include <memory.h>

typedef unsigned char Byte;
typedef unsigned short UInt16;
typedef unsigned int UInt32;
typedef unsigned long long UInt64;

#ifdef __cplusplus

class sshBlob;

class RandomSource
{
public:
    virtual ~RandomSource(){}
    virtual UInt32 Random(void) = 0;
};

class BigNumber
{
private:
    typedef UInt32 DigitType;
    bool _positive;
    DigitType *_digits;
    UInt32 _count;
    
    void Add(const BigNumber &other);
    void Subtract(const BigNumber &other);
    void Multiply(const BigNumber &other);
    void _Divide(const BigNumber &other, BigNumber *remainder);
    int Compare(const BigNumber &other) const;
    void Expand(UInt32 size);
    void Compact(void);
    void CheckSign(void);
    
public:
    BigNumber();
    BigNumber(int simpleValue);
    BigNumber(const BigNumber &original);
    BigNumber(const void *bytes, UInt32 count, bool checkSign = true);
    BigNumber(const UInt32 *data, UInt32 count, bool reverse = false);
    BigNumber(UInt32 bits, RandomSource *source, int primeCertainty);
    ~BigNumber();
    
    sshBlob* Data(void);
    void Print(FILE *file);
    
    // Special functions

    BigNumber Divide(const BigNumber &divisor, BigNumber &modulus) const
    {
        BigNumber result = *this;
        result._Divide(divisor, &modulus);
        return result;
    }
    BigNumber PowerMod(const BigNumber &pow, const BigNumber &mod) const;

    bool IsProbablePrime(int certainty);
    int GetLowestSetBit(void);
    int BitLength(void);
    int AsInt(void);
    
    // A big pile of operators
    
    bool operator[](UInt32 index) const;
    BigNumber& operator=(const BigNumber &other)    // Copy assignment
    {
        if (this != &other) {
            if (_count != other._count) {
                delete[] _digits;
                _count = other._count;
                _digits = new DigitType[_count];
            }
            memcpy(_digits, other._digits, sizeof(DigitType) * _count);
            _positive = other._positive;
        }
        return *this;
    }
    BigNumber& operator=(BigNumber &&other) // Move assignment
    {
        DigitType *tempDigits = other._digits;
        bool tempPositive = other._positive;
        UInt32 tempCount = other._count;
        other._digits = _digits;
        other._positive = _positive;
        other._count = _count;
        _digits = tempDigits;
        _positive = tempPositive;
        _count = tempCount;
        return *this;
    }
    BigNumber& operator++()
    {
        operator+=(1);
        return *this;
    }
    BigNumber operator++(int)
    {
        BigNumber temp(*this);
        operator++();
        return temp;
    }
    BigNumber& operator--()
    {
        operator-=(1);
        return *this;
    }
    BigNumber operator--(int)
    {
        BigNumber temp(*this);
        operator--();
        return temp;
    }
    BigNumber& operator+=(const BigNumber &rightSide)
    {
        if (_positive == rightSide._positive) {
            Add(rightSide);
        } else {
            if (!_positive) {
                BigNumber temp = *this; // Make a note of our old value
                *this = rightSide;  // Copy right hand side
                Subtract(temp);
            } else {
                Subtract(rightSide);
            }
        }
        return *this;
    }
    friend BigNumber operator+(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide += rightSide;
        return leftSide;
    }
    BigNumber& operator-=(const BigNumber &rightSide)
    {
        if (_positive == rightSide._positive) {
            if (_positive) {
                Subtract(rightSide);
            } else {
                BigNumber temp = *this; // Make a note of our old value
                *this = rightSide;  // Copy right hand side
                Subtract(temp);
            }
        } else {
            Add(rightSide);
        }
        return *this;
    }
    friend BigNumber operator-(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide -= rightSide;
        return leftSide;
    }
    BigNumber& operator*=(const BigNumber &rightSide)
    {
        Multiply(rightSide);
        if (_positive != rightSide._positive)
            _positive = false;
        return *this;
    }
    friend BigNumber operator*(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide *= rightSide;
        return leftSide;
    }
    BigNumber& operator/=(const BigNumber &rightSide)
    {
        _Divide(rightSide, NULL);
        if (_positive != rightSide._positive)
            _positive = false;
        return *this;
    }
    friend BigNumber operator/(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide /= rightSide;
        return leftSide;
    }
    BigNumber& operator%=(const BigNumber &rightSide)
    {
        BigNumber result;
        _Divide(rightSide, &result);
        *this = result; // Replace ourselves with the remainder
        return *this;
    }
    friend BigNumber operator%(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide %= rightSide;
        return leftSide;
    }
    BigNumber& operator&=(const BigNumber &rightSide);
    friend BigNumber operator&(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide &= rightSide;
        return leftSide;
    }
    BigNumber& operator|=(const BigNumber &rightSide);
    friend BigNumber operator|(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide |= rightSide;
        return leftSide;
    }
    BigNumber& operator^=(const BigNumber &rightSide);
    friend BigNumber operator^(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide ^= rightSide;
        return leftSide;
    }
    BigNumber& operator>>=(const BigNumber &rightSide);
    friend BigNumber operator>>(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide >>= rightSide;
        return leftSide;
    }
    BigNumber& operator<<=(const BigNumber &rightSide);
    friend BigNumber operator<<(BigNumber leftSide, const BigNumber &rightSide)
    {
        leftSide <<= rightSide;
        return leftSide;
    }
    BigNumber operator~();
    inline bool operator<(const BigNumber &rightSide) const
    {
        return Compare(rightSide) > 0;
    }
    inline bool operator>(const BigNumber &rightSide) const
    {
        return Compare(rightSide) < 0;
    }
    inline bool operator<=(const BigNumber &rightSide) const
    {
        return Compare(rightSide) >= 0;
    }
    inline bool operator>=(const BigNumber &rightSide) const
    {
        return Compare(rightSide) <= 0;
    }
    inline bool operator==(const BigNumber &rightSide) const
    {
        return Compare(rightSide) == 0;
    }
    inline bool operator!=(const BigNumber &rightSide) const
    {
        return Compare(rightSide) != 0;
    }
};

#endif

#endif /* defined(minissh_Maths_h) */
