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
// File: simonspeck.cc

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "simonspeck.h"

#define LCS _lrotl //left circular shift
#define RCS _lrotr //right circular shift
#define f(x) ((LCS(x,1) & LCS(x,8)) ^ LCS(x,2))
#define R2(x,y,k1,k2) (y^=f(x), y^=k1, x^=f(y), x^=k2)

void Simon128Encrypt(uint64_t pt[], uint64_t ct[], uint64_t k[])
{
  uint64_t i;

  ct[0]= pt[0];
  ct[1]= pt[1];
  for(i= 0; i<68; i+= 2)
    R2(ct[1], ct[0], k[i], k[i+1]);
}

#define R(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)

void Speck128ExpandKeyAndEncrypt(uint64_t pt[], uint64_t ct[], uint64_t K[]) {
  uint64_t i;
  uint64_t B= K[1];
  uint64_t A= K[0];

  ct[0]= pt[0];
  ct[1]= pt[1];
  for(i=0; i<32; i++){
    R(ct[1], ct[0], A);
    R(B, A, i);
  }
}

void Speck128Encrypt(uint64_t pt[], uint64_t ct[], uint64_t k[])
{
  uint64_t i;

  ct[0]= pt[0];
  ct[1]= pt[1];
  for(i= 0; i<32; i++)
    R(ct[1], ct[0], k[i]);
}

/*
  Simon 128
  k:  0x0f0e0d0c0b0a0908 0706050403020100
  pt: 0x6373656420737265 6c6c657661727420
  ct: 0x49681b1e1e54fe3f 65aa832af84e0bbc

  Speck 128
  k:  0x0f0e0d0c0b0a0908 0706050403020100
  pt: 0x6c61766975716520 7469206564616d20
  ct: 0xa65d985179783265 7860fedf5c570d18
 */

