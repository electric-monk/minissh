//
//  Primes.cpp
//  libminissh
//
//  Created by Colin David Munro on 6/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "Primes.h"

namespace minissh::Maths::Primes {

namespace {

template<typename X> X ceiling_divide(X x, X y)
{
    X res = x / y;
    if (x % y)
        res++;
    return res;
}
template<> int ceiling_divide(int x, int y)
{
    div_t res = div(x, y);
    return res.quot + (res.rem ? 1 : 0);
}
template<> long ceiling_divide(long x, long y)
{
    ldiv_t res = ldiv(x, y);
    return res.quot + (res.rem ? 1 : 0);
}
template<> long long ceiling_divide(long long x, long long y)
{
    lldiv_t res = lldiv(x, y);
    return res.quot + (res.rem ? 1 : 0);
}
template<> Maths::BigNumber ceiling_divide(Maths::BigNumber x, Maths::BigNumber y)
{
    Maths::BigNumber rem;
    Maths::BigNumber res = x.Divide(y, rem);
    if (rem != Maths::BigNumber(0))
        res++;
    return res;
}

const Maths::BigNumber ONE(1);
const Maths::BigNumber TWO(2);

}

PrimeSieve::Iterator::Iterator(const PrimeSieve& owner, bool start)
:_owner(owner)
{
    _pos = start ? 2 : _owner._maximum;
}
bool PrimeSieve::Iterator::operator!=(const Iterator& other) const
{
    return _pos != other._pos;
}
PrimeSieve::Iterator& PrimeSieve::Iterator::operator++()
{
    if (_pos < _owner._maximum) {
        do {
            _pos++;
        } while ((_pos < _owner._maximum) && !_owner._data[_pos]);
    }
    return *this;
}
UInt64 PrimeSieve::Iterator::operator*() const
{
    return _pos;
}
    
PrimeSieve::PrimeSieve(Maths::BigNumber maximum)
:_maximum(maximum.AsInt())
{
    _data = new bool[_maximum];
    for (UInt64 i = 2; i < _maximum; i++)
        _data[i] = true;
    UInt64 max = maximum.SquareRoot().AsInt();
    for (UInt64 i = 0; i < max; i++)
        if (_data[i])
            for (UInt64 j = i * i; j < _maximum; j += i)
                _data[j] = false;
}
    
PrimeSieve::~PrimeSieve()
{
    delete[] _data;
}

PrimeSieve::Iterator PrimeSieve::begin()
{
    return Iterator(*this, true);
}

PrimeSieve::Iterator PrimeSieve::end()
{
    return Iterator(*this, false);
}

bool TrialDivision(const Maths::BigNumber& value)
{
    PrimeSieve primes(value.SquareRoot().AsInt());
    for (UInt64 prime : primes)
        if ((value % prime) == 0)
            return false;
    return true;
}

ST_Random_Prime_Result ST_Random_Prime(const int length, const Maths::BigNumber& input_seed, const Hash::AType& hash)
{
    // 1. If (length < 2), then return (FAILURE, 0, 0 {, 0}).
    if (length < 2)
        return {false};
    // 2. If (length >= 33), then go to step 14.
    if (length < 33) {
        // 3. prime_seed = input_seed.
        Maths::BigNumber prime_seed = input_seed;
        // 4. prime_gen_counter = 0.
        Maths::BigNumber prime_gen_counter = 0;
        do {
            // 5. c = Hash(prime_seed) (+) Hash(prime_seed + 1).
            Types::Blob xored = hash.Compute(prime_seed.Data())->XorWith(*hash.Compute((prime_seed + 1).Data()));
            Maths::BigNumber c(xored.Value(), xored.Length());
            // 6. c = 2^(length-1) + (c mod 2^(length-1))
            c = (ONE << (length - 1)) + (c % (ONE << (length - 1)));
            // 7. c = (2 * floor(c/2))+1.
            c = (TWO * (c / TWO)) + ONE;
            // 8. prime_gen_counter = prime_gen_counter + 1.
            prime_gen_counter++;
            // 9. prime_seed = prime_seed + 2.
            prime_seed += TWO;
            // 10. Perform a deterministic primality test on c.
            bool is_prime = TrialDivision(c);
            // 11. If (c is a prime number), then.
            if (is_prime) {
                // 11.1 prime = c.
                Maths::BigNumber prime = c;
                // 11.2 Return (SUCCESS, prime, prime_seed {, prime_gen_counter}.
                return {true, prime, prime_seed, prime_gen_counter};
            }
            // 12. If (prime_gen_counter > (4 * length)), then return (FAILURE, 0, 0 {,0}).
            if (prime_gen_counter > (4 * length))
                return {false};
            // 13. Go to step 5.
        } while (true);
    }
    // 14. (status, c0, prime_seed, prime_gen_counter) = ST_Random_Prime((ceiling(length/2)+1), input_seed).
    ST_Random_Prime_Result result = ST_Random_Prime(ceiling_divide(length, 2) + 1, input_seed, hash);
    Maths::BigNumber c0 = result.prime;
    // 15. If FAILURE is returned, return (FAILURE, 0, 0 {,0}).
    if (!result.status)
        return {false};
    // 16. iterations = ceiling(length / outlen) - 1.
    int iterations = ceiling_divide(length, int(hash.DigestLength())) - 1;
    // 17. old_counter = prime_gen_counter.
    Maths::BigNumber old_counter = result.prime_gen_counter;
    // 18. x = 0
    Maths::BigNumber x = 0;
    // 19. For i = 0 to iterations do x = x + (hash(prime_seed + i) * 2^(i*outlen)).
    for (int i = 0; i < iterations; i++) {
        Types::Blob hashed = *hash.Compute((result.prime_seed + i).Data());
        Maths::BigNumber value(hashed.Value(), hashed.Length());
        x += value * (ONE << (i * int(hash.DigestLength())));
    }
    // 20. prime_seed = prime_seed + iterations + 1.
    result.prime_seed += iterations + 1;
    // 21. x = 2^(length-1)+(x mod 2^(length-1)).
    Maths::BigNumber pow2 = ONE << (length - 1);
    x = pow2 + (x % pow2);
    // 22. t = ceiling(x/(2*c0)).
    Maths::BigNumber t = ceiling_divide(x, (TWO * c0));
    do {
        // 23. If (2tc0 + 1 > 2^length), then t=ceiling(2^(length-1)/(2c0)).
        if ((TWO * t * c0 + ONE) > (ONE << length))
            t = ceiling_divide(ONE << (length - 1), (TWO * c0));
        // 24. c = 2tc0+1.
        Maths::BigNumber c = TWO * t * c0 + Maths::BigNumber(1);
        // 25. prime_gen_counter = prime_gen_counter + 1.
        result.prime_gen_counter++;
        // 26. a = 0.
        Maths::BigNumber a = 0;
        // 27. For i = 0 to iterations do a = a + Hash(prime_seed + i) * 2^(i * outlen)).
        for (int i = 0; i < iterations; i++) {
            Types::Blob hashed = *hash.Compute((result.prime_seed + i).Data());
            Maths::BigNumber value(hashed.Value(), hashed.Length());
            a += value * ONE << (i * int(hash.DigestLength()));
        }
        // 28. prime_seed = prime_seed + iterations + 1.
        result.prime_seed += iterations + 1;
        // 29. a = 2 + (a mod (c - 3)).
        a = TWO + (a % (c - 3));
        // 30. z = a^2t mod c.
        Maths::BigNumber z = a.PowerMod(TWO * t, c);
        // 31. If ((1 == GCD(z - 1, c) and (1 = z^c0 mod c)) then
        if ((ONE == (z - ONE).GCD(c)) && (ONE == z.PowerMod(c0, c))) {
            // 31.1 prime = c.
            result.prime = c;
            // 31.2 Return (SUCCESS, prime, prime_seed {,prime_gen_counter}).
            return result;
        }
        // 32. If (prime_gen_counter >= ((4 * length) + old_counter)), then return (FAILURE, 0, 0 {,0}).
        if (result.prime_gen_counter >= ((Maths::BigNumber(4) * length) + old_counter))
            return {false};
        // 33. t = t + 1.
        t++;
        // 34. Go to step 23.
    } while (true);
}

Maths::BigNumber GetPrime(IRandomSource& random, const int length)
{
    // 160 is the length of a seed for SHA1
    ST_Random_Prime_Result result;
    for (int i = 0; i < 10; i++) {
        result = ST_Random_Prime(length, Maths::BigNumber(160, random), Hash::SHA1());
        if (result.status)
            break;
    }
    if (!result.status)
        throw new std::runtime_error("Couldn't make a prime");
    return result.prime;
}

} // namespace minissh::Maths::Primes
