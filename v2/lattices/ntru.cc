// Copyright 2020 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: ntru.cc

#include "crypto_support.h"
#include "lattice.h"

// R = Z[x]/(x^N-1), Rp = Zp[x]/(x^N-1)
// Parameters N, q, d, p 
//  q > (6d+1), (N, q) =1= (p,q), T(d1, d2): polys of deg < N, d1 equal to 1, d2 equal t0 -1, the rest 0
//  Key
//    f in T(d+1,d), g in T(d,d).  f fp = 1 (p), f fq = 1 (q), h=fq g (q)
//  Encrypt
//    m(x) is poly of deg <N coeff between -((p-1)/2) and ((p-1)/2)
//    PK (N, p, q, h) im Rp
//    c = prh + m (q)
//  Decrypt
//    a = f c (q), a between -((p-1)/2) and ((p-1)/2)
//    m = fp a (p), a = f c = f(prh + m) (q)
//    coeff  at most p(2d) + (2d+1)p/2
class ntru {
public:
};
