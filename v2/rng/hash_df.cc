/ Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: hash_df.cc

#include "crypto_support.h"
#include "sha256.h"
#include "hash_df.h"

void hash_all(int byte_size_in, byte* in, byte* out) {
  sha256.h hash_obj;

  hash_obj.init();
  hash_obj.add_to_hash(byte_size_in, in);
  hash_obj.finalize();
  hash_obj.get_digest(sha256::DIGESTBYTESIZE, out);
}

void hash_df(int byte_size_in, byte* in, int bit_size_out, byte* out) {
  sha256.h hash_obj;

  memset(out, 0, sha256::DIGESTBYTESIZE);
  int byte_size_out = (bit_size_out + NBITSINBYTE - 1) / NBITSINBYTE;
  int l = byte_size_out / sha256::DIGESTBYTESIZE;
  int bytes_so_far = 0;
  byte extra_out[sha256::DIGESTBYTESIZE];
  byte ctr = 1;

  for (int i = 0; i < l; i++) {
    hash_obj.init();
    hash_obj.add_to_hash(1, &ctr);
    hash_obj.add_to_hash(sizeof(int), (byte*)&bit_size_out);
    hash_obj.add_to_hash(byte_size_in, in);
    hash_obj.finalize();
    hash_obj.get_digest(hash_byte_output_size_, &out[bytes_so_far]);
    bytes_so_far += sha256::DIGESTBYTESIZE;
    ctr++;
  }
  // partial block --- avoid overflow
  if (bytes_so_far < byte_size_out) {
    hash_obj.init();
    hash_obj.add_to_hash(1, &ctr);
    hash_obj.add_to_hash(sizeof(int), (byte*)&bit_size_out);
    hash_obj.add_to_hash(byte_size_in, in);
    hash_obj.finalize();
    hash_obj.get_digest(sha256::DIGESTBYTESIZE, extra_out);
    int n = 0;
    while (byte_size_out > bytes_so_far) {
      out[bytes_so_far] = extra_out[n++];
    bytes_so_far++;
    }
  }
}

