//
//  Primes.h
//  libminissh
//
//  Created by Colin David Munro on 6/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Maths.h"
#include "Hash.h"

namespace minissh::Maths::Primes {

struct ST_Random_Prime_Result {
    bool status;
    Maths::BigNumber prime;
    Maths::BigNumber prime_seed;
    Maths::BigNumber prime_gen_counter;
};

/**
 * Enumerator for primes up to a given maximum. Works nicely with C++ foreach.
 */
class PrimeSieve
{
private:
    UInt64 _maximum;
    bool *_data;
public:
    class Iterator
    {
    private:
        const PrimeSieve &_owner;
        UInt64 _pos;
    public:
        Iterator(const PrimeSieve& owner, bool start);
        bool operator!=(const Iterator& other) const;
        Iterator& operator++();
        UInt64 operator*() const;
    };
    
    PrimeSieve(Maths::BigNumber maximum);
    ~PrimeSieve();
    
    Iterator begin();
    Iterator end();
};

/**
 * Trial Division per FIPS 186.3 section C.7.
 *
 * Prove an integer to be prime by showing that it has no prime factors less than or equal to its square root.
 * Returns true if prime.
 */
bool TrialDivision(const Maths::BigNumber& value);

/**
 * Shawe-Taylor Random_Prime Routine, per FIPS 186.3 section C.6.
 *
 * Input:
 *  - length: Bit length of requested prime
 *  - input_seed: The seed to be used for the generation of the requested prime.
 * Output:
 *  - status: SUCCESS (true) or FAILURE (false).
 *  - prime: The requested prime.
 *  - prime_seed: A seed determined during generation.
 *  - prime_gen_counter: A counter determined during the generation of the prime.
 */
ST_Random_Prime_Result ST_Random_Prime(const int length, const Maths::BigNumber& input_seed, const Hash::AType& hash);

} // namespace minissh::Maths::Primes
