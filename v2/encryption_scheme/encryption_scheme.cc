// Copyright 2020 John Manferdelli, All Rights Reserved.
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
  clear();
  delete counter_nonce_;
}

bool encryption_scheme::recover_encryption_scheme_from_message() {
  if (scheme_msg_ == nullptr)
    return false;

  if (!scheme_msg_->has_scheme_type())
    return false;
  if (strcmp(scheme_msg_->scheme_type().c_str(), "aes-hmac-sha256-ctr") == 0) {
    alg_.assign("aes-hmac-sha256-ctr");
    enc_alg_name_.assign("aes");
    hmac_alg_name_.assign("hmac-sha256");
    mode_ = CTR;
    pad_ = SYMMETRIC_PAD;
  } else if (strcmp(scheme_msg_->scheme_type().c_str(), "aes-hmac-sha256-cbc") == 0) {
    alg_.assign("aes-hmac-sha256-cbc");
    enc_alg_name_.assign("aes");
    hmac_alg_name_.assign("hmac-sha256");
    mode_ = CBC;
    pad_ = SYMMETRIC_PAD;
  } else  {
    return false;
  }
  if (!scheme_msg_->has_encryption_key())
    return false;
  if (!scheme_msg_->has_parameters())
    return false;
  if (!scheme_msg_->encryption_key().has_key_size())
    return false;
  if (!scheme_msg_->encryption_key().has_secret())
    return false;
  if (!scheme_msg_->parameters().has_size())
    return false;
  if (!scheme_msg_->parameters().has_secret())
    return false;

  enc_key_size_= scheme_msg_->encryption_key().key_size();
  hmac_key_size_ = scheme_msg_->parameters().size();
  encryption_key_.assign(scheme_msg_->encryption_key().secret());
  hmac_key_.assign(scheme_msg_->parameters().secret());
  return true;
}

bool encryption_scheme::get_encryption_scheme_message(string* s) {
  if (scheme_msg_ == nullptr)
    return false;
  return scheme_msg_->SerializeToString(s);
}

bool encryption_scheme::init_nonce(int size, byte* value) {
#if 0
printf("init_nonce: ");print_bytes(size, value);
#endif

  initial_nonce_.clear();
  running_nonce_.clear();

  if (size_nonce_bytes_ > block_size_)
      size_nonce_bytes_ = block_size_;

  if (mode_ == CTR) {
    counter_nonce_->zero_num();
    memcpy(counter_nonce_->value_ptr(), value, size);
    counter_nonce_->normalize();
    fill_big_num_to_block(block_size_, *counter_nonce_, &initial_nonce_);
  } else {
    if (size < block_size_) {
      initial_nonce_.assign((char*)value, size);
      initial_nonce_.append(block_size_ -  size, 0);
    } else {
      initial_nonce_.assign((char*)value, block_size_);
    }
  }
  running_nonce_.assign(initial_nonce_.data(), block_size_);
  nonce_data_valid_ = true;
  return true;
}

bool encryption_scheme::init() {
  enc_key_size_bytes_ = (enc_key_size_ + NBITSINBYTE - 1) / NBITSINBYTE;
  hmac_key_size_bytes_= (hmac_key_size_ + NBITSINBYTE - 1) / NBITSINBYTE;
#if 0
printf("hmac_key_size_: %d, hmac_key_size_bytes_: %d\n", hmac_key_size_, hmac_key_size_bytes_);
print_bytes(hmac_key_size_bytes_, (byte*)hmac_key_.data());
#endif

  if (strcmp(enc_alg_name_.c_str(), "aes") == 0) {
    if (!enc_obj_.init(enc_key_size_, (byte*)encryption_key_.data(), aes::BOTH))
      return false;
    block_size_ = aes::BLOCKBYTESIZE;
  } else {
    return false;
  }
  if (strcmp(hmac_alg_name_.c_str(), "hmac-sha256") == 0) {
    if (!int_obj_.init(hmac_key_size_bytes_, (byte*)hmac_key_.data()))
      return false;
    hmac_digest_size_ = sha256::DIGESTBYTESIZE;
    hmac_block_size_ = sha256::BLOCKBYTESIZE;
  } else {
    return false;
  }

  encrypted_bytes_output_ = 0;
  total_bytes_output_ = 0;
  initialized_ = true;
  return initialized_;
}

bool encryption_scheme::encryption_scheme::init(const char* alg, const char* id_name,
        const char* mode, const char* pad, const char* purpose,
        const char* not_before, const char* not_after, const char* enc_alg,
        int size_enc_key, string& enc_key, const char* enc_key_name,
        const char* hmac_alg, int size_hmac_key, string& hmac_key) {

  if (alg == nullptr)
    return false;
  alg_.assign(alg);
  enc_key_size_ = size_enc_key;
  hmac_key_size_ = size_hmac_key;
  enc_alg_name_.assign(enc_alg);
  hmac_alg_name_.assign(hmac_alg);
  encryption_key_.assign(enc_key);
  hmac_key_.assign(hmac_key);

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

  scheme_msg_ = make_scheme(alg, id_name, mode, pad, purpose,
      not_before, not_after, enc_alg, size_enc_key, enc_key,
      enc_key_name, hmac_alg, size_hmac_key, hmac_key);
  if (scheme_msg_ == nullptr)
    return false;
  initialized_ = init();
  return initialized_;
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

  string nonce(block_size, 0);
  if (crypto_get_random_bytes(block_size_, (byte*)nonce.data()) < block_size)
    return false;
  if (!init_nonce((int)nonce.size(), (byte*)nonce.data()))
    return false;
  // first, output nonce
  memcpy(cur_out, (byte*)initial_nonce_.data(), block_size);
#if 0
printf("First hash: "); print_bytes(block_size_, cur_out);
#endif
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

  // first, get nonce and transform it
  if (!init_nonce(block_size_, in))
    return false;
#if 0
printf("First hash: "); print_bytes(block_size, in);
#endif
  int_obj_.add_to_inner_hash(block_size, in);
  initial_nonce_.assign((char*)in, block_size);
  running_nonce_.assign((char*)in, block_size);
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
    printf("Blocks left is wrong\n");
    return false;
  }

  int additional_bytes = size_out - total_bytes_output_;
  byte computed_mac[mac_size];
  memset(computed_mac, 0, mac_size);
  if (!finalize_decrypt(bytes_left, cur_in, &additional_bytes, cur_out, computed_mac)) {
    printf("finalize_decrypt failed\n");
    return false;
  }
  total_bytes_output_ += additional_bytes;
  encrypted_bytes_output_ += additional_bytes;
  cur_out += additional_bytes;
  cur_in += additional_bytes;
  bytes_left -= additional_bytes;

printf("cur_in: "); print_bytes(bytes_left, cur_in);
printf("cur_out: "); print_bytes(bytes_left, cur_out);

  // now fix message size
  byte* pb = cur_out - 1;
  int i;
  for (i = 0; i < block_size_; i++) {
    if (*pb != 0) {
      if (*pb != 0x80) {
        printf("bad pad 1\n");
        message_valid_= false;
        return false;
      }
      encrypted_bytes_output_ -= (i + 1);
      break;
    }
    pb--;
  }
  if (i >= block_size_) {
    printf("bad pad 2\n");
    message_valid_= false;
    return false;
  }

  message_valid_ = (memcmp(cur_in, computed_mac, hmac_digest_size_) == 0);
#if 0
if (message_valid_)printf("message valid\n"); else printf("message not valid\n");
print_bytes(hmac_digest_size_, computed_mac);
print_bytes(hmac_digest_size_, cur_in);
#endif
  return message_valid_;
}

const int file_buffer_size = 4096;

bool encryption_scheme::encrypt_file(const char* infile, const char* outfile) {

  file_util in_file;
  file_util out_file;

  if (!in_file.open(infile)) {
    printf("Can't open %s\n", infile);
    return false;
  }
  if (out_file.create(outfile)) {
    printf("Can't creat %s\n", outfile);
    return false;
  }

  byte in_buf[file_buffer_size];
  byte out_buf[file_buffer_size];

  if (!message_info(in_file.bytes_in_file(), encryption_scheme::ENCRYPT))
    return false;

  int block_size = get_block_size();
  int num_blocks_in_buffer = file_buffer_size / block_size;
  int bytes_left_in_buffer = 0;
  int bytes_left_in_file = in_file.bytes_in_file();
  int bytes_in_output_buffer= 0;

  string nonce(block_size, 0);
  if (crypto_get_random_bytes(block_size_, (byte*)nonce.data()) < block_size)
    return false;
  if (!init_nonce((int)nonce.size(), (byte*)nonce.data()))
    return false;

  // process nonce block
  int_obj_.add_to_inner_hash(block_size_, (byte*)nonce.data());
  out_file.write_a_block(block_size, (byte*)nonce.data());
  total_bytes_output_ += block_size;

  byte* cur_in;
  byte* cur_out;

  for(;;) {
    if (bytes_left_in_buffer <= 0) {
      if (bytes_in_output_buffer > 0) {
         out_file.write_a_block(bytes_in_output_buffer, out_buf);
      }
      bytes_left_in_buffer = in_file.read_a_block(num_blocks_in_buffer * block_size, in_buf);
      if (bytes_left_in_buffer <= 0) {
          return false;
      }
      cur_in = in_buf;
      cur_out = out_buf;
      bytes_in_output_buffer = 0;
    }

    while (bytes_left_in_buffer > 0) {
      if (bytes_left_in_file < block_size) {
        if (bytes_in_output_buffer > 0) {
          out_file.write_a_block(bytes_in_output_buffer, out_buf);
          bytes_in_output_buffer = 0;
          cur_out = out_buf;
        }
        if (bytes_left_in_buffer == 0) {
          // make sure buffer is filled
          break;
        }
        int additional_bytes = num_blocks_in_buffer * block_size;
        if (!finalize_encrypt(bytes_left_in_buffer, cur_in, &additional_bytes, cur_out)) {
          return false;
        }
        total_bytes_output_ += additional_bytes;
        encrypted_bytes_output_ += additional_bytes - get_mac_size();
        message_valid_ = true;
        in_file.close();
        out_file.close();
        return message_valid_;
      }
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
      bytes_left_in_file -= block_size;
      bytes_in_output_buffer += block_size;
    }
  }
  return true;
}

bool encryption_scheme::decrypt_file(const char* infile, const char* outfile) {

  file_util in_file;
  file_util out_file;

  if (!in_file.open(infile)) {
    printf("Can't open %s\n", infile);
    return false;
  }
  if (out_file.create(outfile)) {
    printf("Can't creat %s\n", outfile);
    return false;
  }

  byte in_buf[file_buffer_size];
  byte out_buf[file_buffer_size];
    return false;

  int mac_size = get_mac_size();
  int block_size = get_block_size();
  int num_blocks = file_buffer_size / block_size;
  int bytes_left_in_buffer = 0;
  int bytes_left_in_file = in_file.bytes_in_file();
  int bytes_in_output_buffer= 0;

  if (!message_info(in_file.bytes_in_file(), encryption_scheme::DECRYPT))

  // read nonce and process it
  if (in_file.read_a_block(block_size, in_buf) < block_size)
    return false;
  if (!init_nonce(block_size, in_buf))
    return false;
  int_obj_.add_to_inner_hash(block_size, in_buf);
  initial_nonce_.assign((char*)in_buf, block_size);
  running_nonce_.assign((char*)in_buf, block_size);
  bytes_left_in_file -= block_size;
  if (mode_ == CTR) {
    // big--> little endian
    reverse_bytes(block_size, in_buf, (byte*)counter_nonce_->value_ptr());
    counter_nonce_->normalize();
  }

  byte* cur_in;
  byte* cur_out;

  for(;;) {
    if (bytes_left_in_buffer <= 0) {
      if (bytes_in_output_buffer > 0) {
         out_file.write_a_block(bytes_in_output_buffer, out_buf);
      }
      bytes_left_in_buffer = in_file.read_a_block(num_blocks * block_size, in_buf);
      if (bytes_left_in_buffer <= 0) {
          return false;
      }
      cur_in = in_buf;
      cur_out = out_buf;
      bytes_in_output_buffer = 0;
    }

    while (bytes_left_in_buffer > 0) {
      if (bytes_left_in_file <= (block_size + mac_size)) {
        if (bytes_in_output_buffer > 0) {
          out_file.write_a_block(bytes_in_output_buffer, out_buf);
          bytes_in_output_buffer = 0;
          cur_out = out_buf;
        }
        if (bytes_left_in_buffer < (block_size + mac_size)) {
          // make sure buffer is filled
          memcpy(in_buf, cur_in, bytes_left_in_buffer);
          int n = in_file.read_a_block(num_blocks * block_size, &in_buf[bytes_left_in_buffer]);
          cur_in = in_buf;
          bytes_left_in_buffer += n;
          break;
        }
        int additional_bytes = num_blocks * block_size;
        byte computed_mac[mac_size];
        memset(computed_mac, 0, mac_size);
        if (!finalize_decrypt(bytes_left_in_buffer, cur_in, &additional_bytes, cur_out, computed_mac)) {
          in_file.close();
          out_file.close();
          return false;
        }
        total_bytes_output_ += additional_bytes;
        encrypted_bytes_output_ += additional_bytes;
        cur_out += additional_bytes;
        cur_in += additional_bytes;
        bytes_left_in_file -= additional_bytes;
        bytes_left_in_buffer -= additional_bytes;

        // now fix message size
        byte* pb = cur_out - 1;
        int i;
        for (i = 0; i < block_size_; i++) {
          if (*pb != 0) {
            if (*pb != 0x80) {
              message_valid_= false;
              in_file.close();
              out_file.close();
              return false;
            }
            encrypted_bytes_output_ -= (i + 1);
            break;
          }
          pb--;
        }
        if (i >= block_size_) {
          message_valid_= false;
          in_file.close();
          out_file.close();
          return false;
        }
        message_valid_ = (memcmp(cur_in, computed_mac, hmac_digest_size_) == 0);
#if 0
if (message_valid_)printf("message valid\n"); else printf("message not valid\n");
print_bytes(hmac_digest_size_, computed_mac);
print_bytes(hmac_digest_size_, cur_in);
#endif
        in_file.close();
        out_file.close();
        return (message_valid_);
      }

    if (mode_ == CTR) {
        ctr_decrypt_step(cur_in, cur_out);
      } else if (mode_ == CBC) {
        cbc_decrypt_step(cur_in, cur_out);
      } else {
        in_file.close();
        out_file.close();
        return false;
      }

      encrypted_bytes_output_ += block_size;
      total_bytes_output_ += block_size;
      cur_in += block_size;
      cur_out += block_size;
      bytes_left_in_file -= block_size;
      bytes_in_output_buffer += block_size;
    }
  }

  return true;
}

