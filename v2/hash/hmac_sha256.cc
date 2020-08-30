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
// File: hmac_sha256.cc

#include "crypto_support.h"
#include "sha256.h"
#include "hmac_sha256.h"

/*
 * if keylen>digestsize
 *   key= digest(key)
 * zerofill key if < digestsize
 * H((K^opad)|H((K^ipad)|text))
 *  ipad = the byte 0x36 repeated sizeofblock  times
 *  opad = the byte 0x5C repeated sizeofblock  times.
 */

hmac_sha256::hmac_sha256() {
  macvalid_ = false;
}

hmac_sha256::~hmac_sha256() {
  memset(key_, 0, BLOCKBYTESIZE);
  memset(mac_, 0, MACBYTESIZE);
  macvalid_ = false;
}

bool hmac_sha256::init(int size, byte* key) {
  if (size <= 0 || key == nullptr)
    return false;
  macvalid_ = false;

  int i;
  byte padded[sha256::BLOCKBYTESIZE];
  memset(key_, 0, sha256::BLOCKBYTESIZE);
  memset(padded, 0, sha256::BLOCKBYTESIZE);

  if (size > sha256::BLOCKBYTESIZE) {
    sha256 compressed_key;
    compressed_key.init();
    compressed_key.add_to_hash(size, key);
    compressed_key.finalize();
    compressed_key.get_digest(sha256::BLOCKBYTESIZE, key_);
  } else {
    memcpy(key_, key, size);
    memset(&key_[size], 0, sha256::BLOCKBYTESIZE - size);
  }
  for (i = 0; i < sha256::BLOCKBYTESIZE; i++) padded[i] = key_[i] ^ 0x36;
  if (!inner_sha256_.init()) {
    return false;
  }
  inner_sha256_.add_to_hash(sha256::BLOCKBYTESIZE, (byte*)padded);
  return true;
}

void hmac_sha256::add_to_inner_hash(int size, byte* in) {
  inner_sha256_.add_to_hash(size, in);
}

bool hmac_sha256::get_hmac(int size, byte* out) {
  if (size < MACBYTESIZE)
    return false;
#ifndef BIGENDIAN
 uint32_t* p_mac = (uint32_t*)mac_;
 uint32_t* p_out = (uint32_t*)out;
 for(int i = 0; i < 8; i++)
    little_to_big_endian_32(&p_mac[i], &p_out[i]);
#else
  memcpy(out, mac_, MACBYTESIZE);
#endif
  return true;
}

void hmac_sha256::finalize() {
  int i;
  byte padded[BLOCKBYTESIZE];
  byte inner_hash[sha256::DIGESTBYTESIZE];
#ifndef BIGENDIAN
  byte inner_hash2[sha256::DIGESTBYTESIZE];
#endif

  inner_sha256_.finalize();
  if (!inner_sha256_.get_digest(sha256::DIGESTBYTESIZE, inner_hash)) {
    return;
  }
  for (i = 0; i < BLOCKBYTESIZE; i++) padded[i] = key_[i] ^ 0x5c;

  sha256 outer_hash;
  outer_hash.init();
  outer_hash.add_to_hash(sha256::BLOCKBYTESIZE, padded);
#ifndef BIGENDIAN
  uint32_t* p_inner_hash = (uint32_t*)inner_hash;
  uint32_t* p_inner_hash2 = (uint32_t*)inner_hash2;
  for(int i = 0; i < 8; i++)
    little_to_big_endian_32(&p_inner_hash[i], &p_inner_hash2[i]);
  outer_hash.add_to_hash(sha256::DIGESTBYTESIZE, inner_hash2);
#else
  outer_hash.add_to_hash(sha256::DIGESTBYTESIZE, inner_hash);
#endif
  outer_hash.finalize();
  outer_hash.get_digest(sha256::DIGESTBYTESIZE, mac_);
  macvalid_ = true;
}
