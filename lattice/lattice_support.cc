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
// File: rc4.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "math.h"
#include "lattice_support.h"

// double exp (double x)
// double log (double x)
// long int random (void)
// double sqrt (double x)

bool RejectNormal(double x, double mean, double var) {
  double t = (x - mean);
  t *= t;
  t /= 2.0 * var;
  // probability of acceptance
  double p = exp(-t);
  printf("Pr(x = %10.7f) = %10.7f\n", t, p);
  // get a random number, r, between 0 and 1
  // accept if r <= p

  long int flip = random();
  long int denom = 0x7fffffffL;
  double test_p = ((double) flip) / ((double) denom);
  printf("%ld/%ld, test_p = %10.7f\n", flip, denom, test_p);
  return (test_p <= p);
}


