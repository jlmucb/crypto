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
// File: lwe.cc

#include "crypto_support.h"
#include "lattice.h"

// m, n, q, m >=n,  chi is error dist, s.  M= {0,1}^l
// C = Zq^n Zq^l
// S in Zq^(m x l), A in Zq^(m x n), E in Zq^(m x l).
// E is chosen from chi.
// P = AS+E
// Encrypt:
//    v in {0,1}^l, a in {0,1}^m (random)
//    (u=A^Ta, P^Ta+close(q/2)v)
//  Decrypt
//    D = close(close(q/2)^(-1)) (c - S^Tu) mod 2
class lwe {
public:
};
