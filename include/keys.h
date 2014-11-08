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
// File: keys.h

#include "cryptotypes.h"
#include "ecc.h"
#include "keys.pb.h"
#include "util.h"
#include <cmath>
#include <string>
#include <iostream> 
#include <fstream>
#include "bignum.h"

#ifndef _CRYPTO_KEYS_H__
#define _CRYPTO_KEYS_H__
using namespace std;

class CryptoKey {
public:
  bool        key_valid_;
  string*     key_name_;
  string*     key_type_;
  string*     key_usage_;
  string*     key_owner_;
  TimePoint*  not_before_;
  TimePoint*  not_after_;

 CryptoKey();
  virtual ~CryptoKey();

  bool     ReadKey(string& filename);
  bool     SaveKey(string& filename);
  bool     SerializeKeyToMessage(crypto_key_message&);
  bool     DeserializeKeyFromMessage(crypto_key_message&);
  void     PrintKey();
};

class SymmetricKey : public CryptoKey {
public:
  string*  symmetric_algorithm_type_;
  int32_t  symmetric_key_bit_size_;
  byte*    symmetric_key_bytes_;
  SymmetricKey();
  ~SymmetricKey();

  bool    GenerateAesKey(const char* name, const char* usage, 
                         const char* owner, int num_bits, 
                         double seconds_to_live);
  bool    MakeAesKey(const char* name, const char* usage, 
                     const char* owner, int num_bits, double secondstolive,
                     byte* key);
  bool    GenerateTwofishKey(const char* name, const char* usage,
                         const char* owner, int num_bits,
                         double seconds_to_live);
  bool    MakeTwofishKey(const char* name, const char* usage,
                     const char* owner, int num_bits, double secondstolive,
                     byte* key);
  bool    ReadKey(string& filename);
  bool    SaveKey(string& filename);

  bool    SerializeKeyToMessage(crypto_symmetric_key_message&);
  bool    DeserializeKeyFromMessage(crypto_symmetric_key_message&);
  void    PrintKey();
};

class RsaKey : public CryptoKey {
public:
  int   bit_size_modulus_;
  int     r_;
  BigNum* m_;
  BigNum* e_;
  BigNum* d_;
  BigNum* p_;
  BigNum* q_;
  BigNum* dp_;
  BigNum* dq_;
  BigNum* m_prime_;
  BigNum* p_prime_;
  BigNum* q_prime_;

  RsaKey();
  ~RsaKey();

  bool    GenerateRsaKey(const char* name, const char* usage, 
                         const char* owner, int num_bits, 
                         double seconds_to_live);
  bool    MakeRsaKey(const char* name, const char* usage, 
                     const char* owner, int num_bits, double secondstolive,
                     BigNum& m, BigNum& e, BigNum& p, BigNum& q);

  bool    ComputeFastDecryptParameters();
  bool    ReadKey(string& filename);
  bool    SaveKey(string& filename);

  bool    SerializeKeyToMessage(crypto_rsa_key_message&);
  bool    DeserializeKeyFromMessage(crypto_rsa_key_message&);
  void    PrintKey();

  bool    Encrypt(int size_in, byte* in, int* size_out, byte* out, int speed= 0);
  bool    Decrypt(int size_in, byte* in, int* size_out, byte* out, int speed= 0);
};

class EccKey : public CryptoKey {
public:
  int         bit_size_modulus_;
  EccCurve    c_;
  BigNum*     a_;
  CurvePoint  g_;
  BigNum*     order_of_g_;
  CurvePoint  base_;  // base_ = a_ * g_

  EccKey();
  ~EccKey();
  bool    MakeEccKey(const char* name, const char* usage, 
                     const char* owner, int num_bits, double secondstolive,
                      EccCurve* c, CurvePoint* g, CurvePoint* base, BigNum* order,
                      BigNum* secret);
  bool    ReadKey(string& filename);
  bool    SaveKey(string& filename);

  bool    SerializeKeyToMessage(crypto_ecc_key_message&);
  bool    DeserializeKeyFromMessage(crypto_ecc_key_message&);
  void    PrintKey();

  bool    Encrypt(int size, byte* plain, CurvePoint& pt1, CurvePoint& pt2);
  bool    Decrypt(CurvePoint& pt1, CurvePoint& pt2, int* size, byte* plain);
};

class KeyStore {
public:
  string*                   filename_;
  crypto_key_store_message  store_;
  int                       num_keys_;

  bool    FindKey(const char* keyname, string** key_type, CryptoKey** key);
  bool    AddKey(CryptoKey* key);
  bool    DeleteKey(const char* keyname);
  int     NumKeys();
  bool    ReadStore(const char* filename);
  bool    SaveStore(const char* filename);

  KeyStore();
  ~KeyStore();
};

class Signature {
public:
  char*     encryption_alg_;
  int       size_serialized_;
  byte*     serialized_statement_;
  int       size_signature_;
  byte*     signature_;
  char*     signer_name_;

  Signature();
  ~Signature();

  bool      Serialize(crypto_signature& sig);
  bool      Deserialize(crypto_signature& sig);
  void      PrintSignature();
};



void printcryptoalgs();
void printcryptoschemes();
void printpaddingalgs();
void printmodes();
void printhashalgs();
#endif

