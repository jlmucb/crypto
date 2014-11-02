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
// limitations under the License.
// This code was derived from codewhose license notice is below
// Project: New Cloudproxy Crypto
// File: twofish.h

// Fast,  portable,  and easy-to-use Twofish implementation,   
// Version 0.3. 
// Copyright (c) 2002 by Niels Ferguson. 
// The author hereby grants a perpetual license to everybody to 
// use this code for any purpose as long as the copyright message is included 
// in the source code of this or any derived work. 

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_TWOFISH_H__
#define _CRYPTO_TWOFISH_H__
using namespace std;
 
 
class TwofishKey {
public:
    uint32_t s[4][256];   // pre-computed S-boxes 
    uint32_t K[40];       // Round key words 
};
 
class Twofish : public SymmetricCipher {
    public:
    byte	q_table[2][256];   
    uint32_t	MDS_table[4][256];
    TwofishKey  round_data;

    Twofish();
    ~Twofish();
    bool      Init(int, byte*, int);

    void      initialise_q_boxes();
    void      initialise_mds_tables();
    uint32_t  h(int k, byte L[], int kCycles);
    void      fill_keyed_sboxes(byte S[], int kCycles, TwofishKey* xkey);   

    void      InitKey(const byte aKeyBytes[], int aKeyLength, TwofishKey* aKey);
    void      Encrypt(int size, byte* aPlainText, byte* aCipherText); 
    void      Decrypt(int size, byte* aCipherText, byte* aPlainText); 
    void      EncryptBlock(byte* in, byte* out); 
    void      DecryptBlock(byte* in, byte* out); 
};
#endif
 

