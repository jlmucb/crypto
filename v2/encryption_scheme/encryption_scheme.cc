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
// File: encryption_scheme.cc

#include "crypto_support.h"
#include "symmetric_cipher.h"
#include "aes.h"
#include "hash.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "encryption_scheme.h"
#include "big_num.h"
#include "big_num_functions.h"


void fill_big_num_to_block(int block_size, big_num& n, string* s) {
  byte buf[128];
  int k = n.size() * sizeof(uint64_t);
  memset(buf, 0, block_size - k);
  memcpy(&buf[block_size - k], (byte*)n.value_ptr(), k);
  // big endian representation
  reverse_bytes_in_place(block_size, buf);
  s->assign((char*)buf, block_size);
}

void xor_into(byte* dst, byte* to_xor, int size) {
  for (int i = 0; i < size; i++)
      dst[i] ^= to_xor[i];
}

void xor_to_dst(byte* src, byte* to_xor, byte* dst, int size) {
  for (int i = 0; i < size; i++)
      dst[i] = src[i] ^ to_xor[i];
}

void encryption_scheme::update_nonce(int size, byte* buf) {
  if (mode_ == CTR) {
    big_unsigned_add_to(*counter_nonce_, big_one);
    fill_big_num_to_block(block_size_, *counter_nonce_, &running_nonce_);
    running_nonce_.assign((char*)counter_nonce_->value_ptr(), block_size_);
    return;
  }
  if (mode_ == CBC) {
    running_nonce_.assign((char*)buf, size);
    return;
  }
}

void encryption_scheme::ctr_encrypt_step(byte* in, byte* out) {
  enc_obj_.encrypt_block((byte*)running_nonce_.data(), out);
  xor_into(out, in, block_size_);
  int_obj_.add_to_inner_hash(block_size_, out);
#if 0
  printf("ctr encrypt in : "); print_bytes(block_size_, in);
  printf("ctr nonce      : "); print_bytes(block_size_, (byte*)running_nonce_.data());
  printf("ctr encrypt out: "); print_bytes(block_size_, out);
#endif
  update_nonce(block_size_, out);
}

void encryption_scheme::ctr_decrypt_step(byte* in, byte* out) {
  int_obj_.add_to_inner_hash(block_size_, in);
  enc_obj_.encrypt_block((byte*)running_nonce_.data(), out);
  xor_into(out, in, block_size_);
#if 0
  printf("ctr decrypt in : "); print_bytes(block_size_, in);
  printf("ctr nonce      : "); print_bytes(block_size_, (byte*)running_nonce_.data());
  printf("ctr decrypt out: "); print_bytes(block_size_, out);
#endif
  update_nonce(block_size_, in);
}

void encryption_scheme::cbc_encrypt_step(byte* in, byte* out) {
  byte tmp[MAXBLOCKSIZE];

  xor_to_dst(in, (byte*)running_nonce_.data(), tmp, block_size_);
  enc_obj_.encrypt_block(tmp, out);
  int_obj_.add_to_inner_hash(block_size_, out);
#if 0
  printf("cbc encrypt in : "); print_bytes(block_size_, in);
  printf("cbc nonce      : "); print_bytes(block_size_, (byte*)running_nonce_.data());
  printf("cbc encrypt out: "); print_bytes(block_size_, out);
#endif
  update_nonce(block_size_, out);
}

void encryption_scheme::cbc_decrypt_step(byte* in, byte* out) {
  byte tmp[MAXBLOCKSIZE];

  int_obj_.add_to_inner_hash(block_size_, in);
  enc_obj_.decrypt_block(in, tmp);
  xor_to_dst(tmp, (byte*)running_nonce_.data(), out, block_size_);
#if 0
  printf("cbc decrypt in : "); print_bytes(block_size_, in);
  printf("cbc nonce      : "); print_bytes(block_size_, (byte*)running_nonce_.data());
  printf("cbc decrypt out: "); print_bytes(block_size_, out);
#endif
  update_nonce(block_size_, in);
}

bool encryption_scheme::message_info(int msg_size, int operation) {
  operation_ = operation;
  total_message_size_ = msg_size;
  return true;
}

int encryption_scheme::get_message_size() {
  return total_message_size_;
}

int encryption_scheme::get_block_size() {
  return block_size_;
}

int encryption_scheme::get_mac_size() {
  return hmac_digest_size_;
}

int encryption_scheme::get_bytes_encrypted() {
  return encrypted_bytes_output_;
}

int encryption_scheme::get_total_bytes_output() {
  return total_bytes_output_;
}

bool encryption_scheme::get_message_valid() {
  return message_valid_;
}

void encryption_scheme::clear() {
  initialized_ = false;
  scheme_msg_ = nullptr;
  initial_nonce_.clear();
  mode_ = encryption_scheme::NONE;
  pad_= encryption_scheme::NONE;
  nonce_data_valid_ = false;
  running_nonce_.clear();
  counter_nonce_->zero_num();
  encrypted_bytes_output_ = 0;
  total_message_size_ = 0;
  operation_ = 0;
  total_bytes_output_ = 0;
  block_size_ = 0;
  hmac_block_size_ = 0;
  hmac_digest_size_ = 0;
  operation_ = 0;
}

encryption_scheme::encryption_scheme() {
  counter_nonce_ = new big_num(10);
  clear();
}

encryption_scheme::~encryption_scheme() {
}

bool encryption_scheme::recover_encryption_scheme_from_message(string& s) {
  return true;
}

bool encryption_scheme::get_encryption_scheme_message(string* s) {
  return true;
}

bool encryption_scheme::encryption_scheme::init(const char* alg, const char* id_name,
        const char* mode, const char* pad, const char* purpose,
        const char* not_before, const char* not_after, const char* enc_alg,
        int size_enc_key, string& enc_key, const char* enc_key_name,
        const char* hmac_alg, int size_hmac_key,  string& hmac_key,
        int size_nonce, string& nonce) {

  if (alg == nullptr)
    return false;

   // NONE = 0, AES= 0x01, SHA2 = 0x01, SYMMETRIC_PAD = 0x01, MODE = 0x01
  if (pad == nullptr)
    return false;
  if (strcmp(pad, "sym-pad") == 0)
    pad_ = SYMMETRIC_PAD;
  else
    return false;

  if (mode == nullptr)
    return false;
  if (strcmp(mode, "ctr") == 0) {
    mode_ = CTR;
  } else if (strcmp(mode, "cbc") == 0) {
    mode_ = CBC;
  } else {
    return false;
  }

  if (strcmp(enc_alg, "aes") == 0) {
    if (!enc_obj_.init(size_enc_key, (byte*)enc_key.data(), aes::BOTH))
      return false;
    block_size_ = aes::BLOCKBYTESIZE;
  } else {
    return false;
  }

  if (strcmp(hmac_alg, "hmac-sha256") == 0) {
    if (!int_obj_.init(size_hmac_key, (byte*)hmac_key.data()))
      return false;
    hmac_digest_size_ = sha256::DIGESTBYTESIZE;
    hmac_block_size_ = sha256::BLOCKBYTESIZE;
  } else {
    return false;
  }

  initial_nonce_.clear();
  running_nonce_.clear();

  int size_nonce_bytes = size_nonce / NBITSINBYTE;
  if (size_nonce_bytes > block_size_)
      size_nonce_bytes = block_size_;

  if (mode_ == CTR) {
    counter_nonce_->zero_num();
    memcpy(counter_nonce_->value_ptr(), (byte*)nonce.data(), size_nonce_bytes);
    counter_nonce_->normalize();
    fill_big_num_to_block(block_size_, *counter_nonce_, &initial_nonce_);
  } else {
    if (((int)nonce.size()) < block_size_) {
      initial_nonce_.assign((char*)nonce.data(), ((int)nonce.size()));
      initial_nonce_.append(block_size_ -  ((int)nonce.size()), 0);
    } else {
      initial_nonce_.assign((char*)nonce.data(), block_size_);
    }
  }
  running_nonce_.assign(initial_nonce_.data(), block_size_);
  nonce_data_valid_ = true;

  encrypted_bytes_output_ = 0;
  total_bytes_output_ = 0;

  scheme_msg_ = make_scheme(alg, id_name, mode, pad, purpose,
      not_before, not_after, enc_alg, size_enc_key, enc_key,
      enc_key_name, hmac_alg, size_hmac_key,  hmac_key, size_nonce, nonce);
  if (scheme_msg_ == nullptr)
    return false;
  return true;
}

bool encryption_scheme::get_nonce_data(int size, byte* out) {
  if (size < (int)initial_nonce_.size())
    return false;
  memcpy(out, (byte*)initial_nonce_.data(), size);
  return true;
}

bool encryption_scheme::encrypt_block(int size_in, byte* in, byte* out) {
  enc_obj_.encrypt_block(in, out);
  return true;
}

bool encryption_scheme::decrypt_block(int size_in, byte* in, byte* out) {
  enc_obj_.decrypt_block(in, out);
  return true;
}

bool encryption_scheme::finalize_encrypt(int size_final, byte* final_in,
      int* size_out, byte* out) {
  int bytes_written = 0;

  // pad final block
  byte final_block[128];
  int n = size_final;
  if (size_final > 0) {
    memcpy(final_block, final_in, n);
  }

  if (n >= block_size_) {
    if (mode_ == CTR) {
      ctr_encrypt_step(final_block, out);
    } else if(mode_ == CBC) {
      cbc_encrypt_step(final_block, out);
    } else {
      return false;
    }
    out += block_size_;
    *size_out -= block_size_;
    bytes_written += block_size_;
    memset(final_block, 0, block_size_);
    n = 0;
  }

  final_block[n++] = 0x80;
  memset(&final_block[n], 0, block_size_ - n);
  if (mode_ == CTR) {
    ctr_encrypt_step(final_block, out);
  } else if(mode_ == CBC) {
    cbc_encrypt_step(final_block, out);
  } else {
    return false;
  }
  out += block_size_;
  *size_out -= block_size_;
  bytes_written += block_size_;
  memset(final_block, 0, block_size_);

  // finalize and append hmac
  int_obj_.finalize();
  if (*size_out < hmac_digest_size_) {
    return false;
  }
  if (!int_obj_.get_hmac(hmac_digest_size_, out)) {
    return false;
  }

  bytes_written += hmac_digest_size_;
  *size_out = bytes_written;
  return true;
}

bool encryption_scheme::finalize_decrypt(int size_final, byte* final_in,
      int* size_out, byte* out, byte* computed_mac) {
  int bytes_written = 0;
  size_final -= get_mac_size();

  if (size_final >= block_size_) {
    if (mode_ == CTR) {
      ctr_decrypt_step(final_in, out);
    } else if(mode_ == CBC) {
      cbc_decrypt_step(final_in, out);
    } else {
      return false;
    }
    out += block_size_;
    final_in += block_size_;
    *size_out = block_size_;
    bytes_written += block_size_;
  }

  // finalize and get hmac
  int_obj_.finalize();
  if (!int_obj_.get_hmac(hmac_digest_size_, computed_mac)) {
    return false;
  }
  *size_out = bytes_written;
  return true;
}

bool encryption_scheme::encrypt_message(int size_in, byte* in, int size_out, byte* out) {
  if (!message_info(size_in, encryption_scheme::ENCRYPT))
    return false;
  byte* cur_in = in;
  byte* cur_out = out;
  int block_size = get_block_size();
  int bytes_left = size_in;

  // first, output nonce, which was set up in init
  memcpy(cur_out, (byte*)initial_nonce_.data(), block_size);
  int_obj_.add_to_inner_hash(block_size_, cur_out);
  cur_out += block_size;
  total_bytes_output_ += block_size;

  while (bytes_left >= block_size) {
    if (mode_ == CTR) {
      ctr_encrypt_step(cur_in, cur_out);
    } else if (mode_ == CBC) {
      cbc_encrypt_step(cur_in, cur_out);
    } else {
        return false;
    }
    encrypted_bytes_output_ += block_size;
    total_bytes_output_ += block_size;
    cur_in += block_size;
    cur_out += block_size;
    bytes_left -= block_size;
  }

  int additional_bytes = size_out - total_bytes_output_;
  if (!finalize_encrypt(bytes_left, cur_in, &additional_bytes, cur_out)) {
    return false;
  }
  total_bytes_output_ += additional_bytes;
  encrypted_bytes_output_ += additional_bytes - get_mac_size();

  message_valid_ = true;
  return true;
}

bool encryption_scheme::decrypt_message(int size_in, byte* in, int size_out, byte* out) {
  if (!message_info(size_in, encryption_scheme::DECRYPT))
    return false;

  byte* cur_in = in;
  byte* cur_out = out;
  int block_size = get_block_size();
  int mac_size = get_mac_size();
  int bytes_left = size_in;

  // first, get nonce and transform it, ignore the nonces in class,
  // they are from encrypt init
  int_obj_.add_to_inner_hash(block_size_, in);
  initial_nonce_.assign((char*)in, block_size_);
  running_nonce_.assign((char*)in, block_size_);
  cur_in += block_size;
  bytes_left -= block_size;
  if (mode_ == CTR) {
    // big--> little endian
    reverse_bytes(block_size_, in, (byte*)counter_nonce_->value_ptr());
    counter_nonce_->normalize();
  }

  while (bytes_left > (block_size + mac_size)) {
    if (mode_ == CTR) {
        ctr_decrypt_step(cur_in, cur_out);
      } else if (mode_ == CBC) {
        cbc_decrypt_step(cur_in, cur_out);
      } else {
        return false;
      }
    encrypted_bytes_output_ += block_size;
    total_bytes_output_ += block_size;
    cur_in += block_size;
    cur_out += block_size;
    bytes_left -= block_size;
  }

  if (bytes_left != (block_size + mac_size)) {
    return false;
}

  int additional_bytes = size_out - total_bytes_output_;
  byte computed_mac[128];
  memset(computed_mac, 0, 128);
  if (!finalize_decrypt(bytes_left, cur_in, &additional_bytes, cur_out, computed_mac)) {
    return false;
  }
  total_bytes_output_ += additional_bytes;
  encrypted_bytes_output_ += additional_bytes;
  cur_out += additional_bytes;
  cur_in += additional_bytes;
  bytes_left -= additional_bytes;

  // now fix message size
  byte* pb = cur_out - 1;
  int i;
  for (i = 0; i < block_size_; i++) {
    if (*pb != 0) {
      if (*pb != 0x80) {
        message_valid_= false;
        return false;
      }
      encrypted_bytes_output_ -= (i + 1);
      break;
    }
    pb--;
  }
  if (i >= block_size_) {
    message_valid_= false;
    return false;
  }

  message_valid_ = (memcmp(cur_in, computed_mac, hmac_digest_size_) == 0);
  return message_valid_;
}
