//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// Project: New Cloudproxy Crypto
// File: lwe_lattice.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "math.h"
#include "lattice_support.h"


/*
 *  q a prime (size: 50 bits)
 *  S, a "secret" n x m matrix with small entries
 *  A, a random n x m matrix
 *  T = AS
 *  H(x) a cryptographic hash
 *
 *  Sign(q, h, A, S)
 *    y = Rand(m, std-dev)
 *    c = H(Ay (mod q, h)
 *    z = SC + y
 *    output (z, c) with probability exp([-2(z, Sc) + ||Sc||^2]/2 sigma)
 *
 *  Verify(q, h, c, A, T)
 *    check ||z|| <= 2 sigma sqrt(m)
 *    Check c == H(Az-Tc)
 *
 *  Parameters
 *    n = 512
 *    S 20K bits
 *    Sig: 200K bits
 */

