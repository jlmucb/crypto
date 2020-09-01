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
// File: pkcs.cc

#include "crypto_support.h"
#include "hash.h"
#include "sha256.h"

/*
 * EMSA-PKCS1-v1_5-ENCODE (M, emLen)
 *   M         message to be encoded
 *   emLen     intended length in octets of the encoded message, at least
 *             ||T|| + 10
 *   Output:
 *    EM        encoded message, an octet string of length emLen; or "message
 *             too long" or "intended encoded message length too short"
 *   1. Apply the hash function to the message M to produce a hash value H:
 *        H = Hash(M).
 *   2. Encode the algorithm ID for the hash function and the hash value
 *      DigestInfo (T)
 *      SHA-256:   30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
 *      SHA-512    30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
 *      SHA1       30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
 *   3. If emLen is less than ||T|| + 10 then output error
 *   4. Generate an octet string PS consisting of emLen-||T||-2 octets with
 * value
 *      FF (hexadecimal). The length of PS will be at least 8 octets.
 *   5. Form the encoded message EM as: EM = 01 || PS || 00 || T || H
 * EME-PKCS1-v1_5 encoding:
 *    a. Generate an octet string PS of length k - mLen - 3 consisting
 *       of pseudo-randomly generated nonzero octets.  The length of PS
 *       will be at least eight octets.
 *    b. Concatenate PS, the message M, and other padding to form an
 *       encoded message EM of length k octets as
 *          EM = 0x00 || 0x02 || PS || 0x00 || M.
 */

byte sha512_digest_info[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
                             0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                             0x03, 0x05, 0x00, 0x04, 0x40};
byte sha256_digest_info[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                             0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                             0x01, 0x05, 0x00, 0x04, 0x20};
byte sha1_digest_info[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                           0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

bool pkcs_encode(const char* hash_alg, byte* hash, int out_size, byte* out) {
  int m = 0;
  int n = 0;
  int size_pad = 0;

  if (strcmp(hash_alg, "sha-1") == 0) {
    n = sizeof(sha1_digest_info);
    size_pad = out_size - (n + 22);
    if ((n + 30) > out_size) {
      return false;
    }
    out[m++] = 0x01;
    memset(&out[m], 0xff, size_pad);
    m += size_pad;
    out[m++] = 0;
    memcpy(&out[m], sha1_digest_info, n);
    m += n;
    memcpy(&out[m], hash, 20);
    return true;
  } else if (strcmp(hash_alg, "sha-256") == 0) {
    n = sizeof(sha256_digest_info);
    size_pad = out_size - (n + 34);
    if ((n + 42) > out_size) {
      return false;
    }
    out[m++] = 0x01;
    memset(&out[m], 0xff, size_pad);
    m += size_pad;
    out[m++] = 0;
    memcpy(&out[m], sha256_digest_info, n);
    m += n;
    memcpy(&out[m], hash, 32);
    return true;
  } else if (strcmp(hash_alg, "sha-512") == 0) {
    n = sizeof(sha512_digest_info);
    size_pad = out_size - (n + 66);
    if ((n + 74) > out_size) {
      return false;
    }
    out[m++] = 0x01;
    memset(&out[m], 0xff, size_pad);
    m += size_pad;
    out[m++] = 0;
    memcpy(&out[m], sha512_digest_info, n);
    m += n;
    memcpy(&out[m], hash, 64);
    return true;
  } else {
    return false;
  }
}

bool pkcs_verify(const char* hash_alg, byte* hash, int in_size, byte* in) {
  int m = 0;
  int n = 0;
  int size_pad = 0;

  if (strcmp(hash_alg, "sha-1") == 0) {
    n = sizeof(sha1_digest_info);
    size_pad = in_size - (n + 22);
    if (in[m++] != 0x01) return false;
    for (int i = 0; i < size_pad; i++) {
      if (in[m++] != 0xff) return false;
    }
    if (in[m++] != 0x00) return false;
    if (memcmp(&in[m], sha1_digest_info, n) != 0) return false;
    m += n;
    if (memcmp(&in[m], hash, 20) != 0) return false;
    return true;
  } else if (strcmp(hash_alg, "sha-256") == 0) {
    n = sizeof(sha256_digest_info);
    size_pad = in_size - (n + 34);
    if (in[m++] != 0x01) return false;
    for (int i = 0; i < size_pad; i++) {
      if (in[m++] != 0xff) return false;
    }
    if (in[m++] != 0x00) return false;
    if (memcmp(&in[m], sha256_digest_info, n) != 0) return false;
    m += n;
    if (memcmp(&in[m], hash, 32) != 0) return false;
    return true;
  } else if (strcmp(hash_alg, "sha-512") == 0) {
    n = sizeof(sha1_digest_info);
    size_pad = in_size - (n + 22);
    if (in[m++] != 0x01) return false;
    for (int i = 0; i < size_pad; i++) {
      if (in[m++] != 0xff) return false;
    }
    if (in[m++] != 0x00) return false;
    if (memcmp(&in[m], sha512_digest_info, n) != 0) return false;
    m += n;
    if (memcmp(&in[m], hash, 64) != 0) return false;
    return true;
  } else {
    return false;
  }
}

bool pkcs_embed(int in_size, byte* in, int out_size, byte* out) {
  int m = 0;
  int pad_size = 0;

  out[m++] = 0;
  out[m++] = 0x02;
  pad_size = out_size - (in_size + 3);
  if (crypto_get_random_bytes(pad_size, &out[m]) != pad_size)
    return false;
  for (int i = 0; i < pad_size; i++) {
    if (out[m + i] == 0) out[m + i] = 1;
  }
  m += pad_size;
  out[m++] = 0;
  memcpy(&out[m], in, in_size);
  return true;
}

bool pkcs_extract(int in_size, byte* in, int* out_size, byte* out) {
  int m = 0;
  int n = 0;
  int size_pad = 0;

  if (in[m++] != 0x00) return false;
  if (in[m++] != 0x02) return false;
  while (size_pad < (in_size - 3) && in[m + size_pad] != 0) size_pad++;
  n = in_size - (size_pad + 3);
  if (n > *out_size) return false;
  m += size_pad;
  if (in[m++] != 0x00) return false;
  *out_size = n;
  memcpy(out, &in[m], n);
  return true;
}
