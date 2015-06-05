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
// File: hmac_sha256.cc

#include "cryptotypes.h"
#include "util.h"
#include "hash.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include <string>
#include <string.h>
#include <stdio.h>

/*
 * if keylen>digestsize
 *   key= digest(key)
 * zerofill key if < digestsize
 * H((K^opad)|H((K^ipad)|text))
 *  ipad = the byte 0x36 repeated sizeofblock  times
 *  opad = the byte 0x5C repeated sizeofblock  times.
 */

HmacSha256::HmacSha256() {
  macvalid_ = false;
}

HmacSha256::~HmacSha256() {
  memset(key_, 0, BLOCKBYTESIZE);
  memset(mac_, 0, MACBYTESIZE);
  macvalid_ = false;
}

bool HmacSha256::Init(int size, byte* key) {
  if (size <= 0 || key == nullptr)
    return false;
  macvalid_ = false;

  int i;
  byte padded[BLOCKBYTESIZE];
  memset(key_, 0, Sha256::BLOCKBYTESIZE);
  memset(padded, 0, BLOCKBYTESIZE);

  if (size > Sha256::BLOCKBYTESIZE) {
    Sha256 compressed_key;
    compressed_key.Init();
    compressed_key.AddToHash(size, (const byte*)key);
    compressed_key.Final();
    compressed_key.GetDigest(Sha256::BLOCKBYTESIZE, key_);
  } else {
    memcpy(key_, key, size);
    memset(&key_[size], 0, BLOCKBYTESIZE - size);
  }
  for (i = 0; i < BLOCKBYTESIZE; i++) padded[i] = key_[i] ^ 0x36;
  if (!inner_sha256_.Init()) {
    return false;
  }
  inner_sha256_.AddToHash(BLOCKBYTESIZE, (const byte*)padded);
  return true;
}

void HmacSha256::AddToInnerHash(int size, const byte* in) {
  inner_sha256_.AddToHash(size, in);
}

bool HmacSha256::GetHmac(int size, byte* out) {
  if (size < MACBYTESIZE)
    return false;
#ifndef BIGENDIAN
  LittleEndian32(8, (const uint32_t*)mac_, (uint32_t*)out);
#else
  memcpy(out, mac_, MACBYTESIZE);
#endif
  return true;
}

void HmacSha256::Final() {
  int i;
  byte padded[BLOCKBYTESIZE];
  byte inner_hash[Sha256::DIGESTBYTESIZE];
#ifndef BIGENDIAN
  byte inner_hash2[Sha256::DIGESTBYTESIZE];
#endif

  inner_sha256_.Final();
  if (!inner_sha256_.GetDigest(Sha256::DIGESTBYTESIZE, inner_hash)) {
    return;
  }
  for (i = 0; i < BLOCKBYTESIZE; i++) padded[i] = key_[i] ^ 0x5c;

  Sha256 outer_hash;
  outer_hash.Init();
  outer_hash.AddToHash(Sha256::BLOCKBYTESIZE, padded);
  LittleEndian32(8, (const uint32_t*)inner_hash, (uint32_t*)inner_hash2);
#ifndef BIGENDIAN
  outer_hash.AddToHash(Sha256::DIGESTBYTESIZE, inner_hash2);
#else
  outer_hash.AddToHash(Sha256::DIGESTBYTESIZE, inner_hash);
#endif
  outer_hash.Final();
  outer_hash.GetDigest(Sha256::DIGESTBYTESIZE, mac_);
  macvalid_ = true;
}
