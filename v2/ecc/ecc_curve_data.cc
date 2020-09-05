//
// Copyright 2014 John Manferdelli, All r_ptights r_pteserved.
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
// File: ecc_curve_data.cc

#include "crypto_support.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "ecc.h"


//  ECC Curve Data
ecc p256_key;
bool p256_key_valid = false;
ecc p384_key;
bool p384_key_valid = false;
ecc p521_key;
bool p521_key_valid = false;


/*
  Curve pt-256:
    p = 1157920892103562487626974469494075735300861434152903141955
        33631308867097853951
    n = 115792089210356248762697446949407573529996955224135760342
        422259061068512044369
    SEED = c49d3608 86e70493
    c = 7efba166 2985be94 af317768 0104fa0d
    b = 5ac635d8 aa3a93e7 3bce3c3e 27d2604b
    G_x = 6b17d1f2 e12c4247 f4a13945 d898c296
    G_y = 4fe342e2 fe1a7f9b cbb64068 37bf51f5

    p = 2^256 − 2^224 + 2^192 + 2^96 − 1:
    (p)_10 = 1157920892103562487626974469494075735300
            86143415290314195533631308867097853951
    (p)_16= ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
    a = p^256 − 3:
    (a)_10 = 1157920892103562487626974469494075735300
            86143415290314195533631308867097853948
    (a)_16 = ffffffff 00000001 00000000 00000000 00000000 ffffffff
            ffffffff fffffffc
    (b)_10 = 4105836372515214212932612978004726840911
            4441015993725554835256314039467401291
    (b)_16 = 5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6
            3bce3c3e 27d2604b
    Base point G:
      (xG)_16 = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0
                f4a13945 d898c296
      (yG)_16 = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece
                cbb64068 37bf51f5
      Order q of the point G (and of the elliptic curve group E):
      (q__16 = ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84
              f3b9cac2 fc632551

  Curve pt-384
    p = 2^384 – 2^128 – 2^96 + 2^32 – 1
    p = 3940200619639447921227904010014361380507973927046544666794
        8293404245721771496870329047266088258938001861606973112319

    n = 3940200619639447921227904010014361380507973927046544666794
        6905279627659399113263569398956308152294913554433653942643
    SEED = a335926a a319a27a 1d00896a 6773a482 7acdac73

    c = 79d1e655 f868f02f ff48dcde e14151dd b80643c1 406d0ca1
        0dfe6fc5 2009540a 495e8042 ea5f744f 6e184667 cc722483
    b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
        0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
    G x = aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
          59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
    G y = 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
          e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f 

  Curve pt-521
    p = 2^521 – 1
    p = 686479766013060971498190079908139321726943530014330540939
        446345918554318339765605212255964066145455497729631139148
        0858037121987999716643812574028291115057151
    n = 686479766013060971498190079908139321726943530014330540939
        446345918554318339765539424505774633321719753296399637136
        3321113864768612440380340372808892707005449
    SEED = d09e8800 291cb853 96cc6717 393284aa a0da64ba
    c = 0b4 8bfa5f42 0a349495 39d2bdfc 264eeeeb 077688e4
        4fbf0ad8 f6d0edb3 7bd6b533 28100051 8e19f1b9 ffbe0fe9
        ed8a3c22 00b8f875 e523868c 70c1e5bf 55bad637
    b = 051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b
        99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd
        3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00
    G x = c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139
          053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127
          a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66
    G y = 118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449
          579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901
          3fad0761 353c7086 a272c240 88be9476 9fd16650
*/

bool init_ecc_curves() {

  time_point* time_now = nullptr;
  time_point* time_later = nullptr;

  // pt-256

  if (!pt256_key_valid) {

    pt256_Key.bit_size_modulus_ = 256;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt256_Key.key_name_ = new string("pt-256");
    pt256_Key.key_type_ = new string("ecc-256");
    pt256_Key.key_usage_ = new string("all");
    pt256_Key.key_owner_ = new string("NIST");
    pt256_Key.not_before_ = time_now;
    pt256_Key.not_after_ = time_later;
  
    pt256_Key.c_.modulus_bit_size_ = 256;
    pt256_Key.c_.p_ = new big_num(4);
    pt256_Key.c_.p_->value_[3] = 0xffffffff00000001ULL;
    pt256_Key.c_.p_->value_[2] = 0ULL;
    pt256_Key.c_.p_->value_[1] = 0x00000000ffffffffULL;
    pt256_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    pt256_Key.c_.p_->normalize();

    pt256_Key.c_.a_ = new big_num(4);
    pt256_Key.c_.a_->value_[3] = 0xffffffff00000001ULL;
    pt256_Key.c_.a_->value_[2] = 0ULL;
    pt256_Key.c_.a_->value_[1] = 0x00000000ffffffffULL;
    pt256_Key.c_.a_->value_[0] = 0xfffffffffffffffcULL;
    pt256_Key.c_.a_->normalize();

    pt256_Key.c_.b_ = new big_num(4);
    pt256_Key.c_.b_->value_[3] = 0x5ac635d8aa3a93e7ULL;
    pt256_Key.c_.b_->value_[2] = 0xb3ebbd55769886bcULL;
    pt256_Key.c_.b_->value_[1] = 0x651d06b0cc53b0f6ULL;
    pt256_Key.c_.b_->value_[0] = 0x3bce3c3e27d2604bULL;
    pt256_Key.c_.b_->normalize();

    pt256_Key.bit_size_modulus_ = 256;
    pt256_Key.order_of_g_ = new big_num(4);
    pt256_Key.order_of_g_->value_[3] = 0xffffffff00000000ULL;
    pt256_Key.order_of_g_->value_[2] = 0xffffffffffffffffULL;
    pt256_Key.order_of_g_->value_[1] = 0xbce6faada7179e84ULL;
    pt256_Key.order_of_g_->value_[0] = 0xf3b9cac2fc632551ULL;
    pt256_Key.order_of_g_->normalize();

    pt256_Key.g_.x_ = new big_num(4);
    pt256_Key.g_.x_->value_[3] = 0x6b17d1f2e12c4247ULL;
    pt256_Key.g_.x_->value_[2] = 0xf8bce6e563a440f2ULL;
    pt256_Key.g_.x_->value_[1] = 0x77037d812deb33a0ULL;
    pt256_Key.g_.x_->value_[0] = 0xf4a13945d898c296ULL;
    pt256_Key.g_.x_->normalize();
    pt256_Key.g_.y_ = new big_num(4);
    pt256_Key.g_.y_->value_[3] = 0x4fe342e2fe1a7f9bULL;
    pt256_Key.g_.y_->value_[2] = 0x8ee7eb4a7c0f9e16ULL;
    pt256_Key.g_.y_->value_[1] = 0x2bce33576b315eceULL;
    pt256_Key.g_.y_->value_[0] = 0xcbb6406837bf51f5ULL;
    pt256_Key.g_.y_->normalize();
    pt256_Key.g_.z_ = new big_num(1, 1ULL);

    pt256_Key.g_.z_->normalize();
    pt256_key_valid = true;
    pt256_Key.base_.x_ = nullptr;
    pt256_Key.base_.y_ = nullptr;
    pt256_Key.base_.z_ = nullptr;
    pt256_Key.key_valid_ = true;
  }

  // pt-384
  if (!pt384_key_valid) {

    pt384_Key.c_.modulus_bit_size_ = 384;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt384_Key.key_name_ = new string("pt-384");
    pt384_Key.key_type_ = new string("ecc-384");
    pt384_Key.key_usage_ = new string("all");
    pt384_Key.key_owner_ = new string("NIST");
    pt384_Key.not_before_ = time_now;
    pt384_Key.not_after_ = time_later;

    // p = 2^384 – 2^128 – 2^96 + 2^32 –1
    pt384_Key.c_.p_ = new big_num(6);
    pt384_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[2] = 0xfffffffffffffffeULL;
    pt384_Key.c_.p_->value_[1] = 0xffffffff00000000ULL;
    pt384_Key.c_.p_->value_[0] = 0x00000000ffffffffULL;
    pt384_Key.c_.p_->normalize();

    pt384_Key.c_.a_ = new big_num(6);
    pt384_Key.c_.a_->value_[5] = 0x79d1e655f868f02fULL;
    pt384_Key.c_.a_->value_[4] = 0xff48dcdee14151ddULL;
    pt384_Key.c_.a_->value_[3] = 0xb80643c1406d0ca1ULL;
    pt384_Key.c_.a_->value_[2] = 0x0dfe6fc52009540aULL;
    pt384_Key.c_.a_->value_[1] = 0x495e8042ea5f744fULL;
    pt384_Key.c_.a_->value_[0] = 0x6e184667cc722483ULL;
    pt384_Key.c_.a_->normalize();

    pt384_Key.c_.b_ = new big_num(6);
    pt384_Key.c_.b_->value_[5] = 0xb3312fa7e23ee7e4ULL;
    pt384_Key.c_.b_->value_[4] = 0x988e056be3f82d19ULL;
    pt384_Key.c_.b_->value_[3] = 0x181d9c6efe814112ULL;
    pt384_Key.c_.b_->value_[2] = 0x0314088f5013875aULL;
    pt384_Key.c_.b_->value_[1] = 0xc656398d8a2ed19dULL;
    pt384_Key.c_.b_->value_[0] = 0x2a85c8edd3ec2aefULL;
    pt384_Key.c_.b_->normalize();

    pt384_Key.bit_size_modulus_ = 384;
    pt384_Key.order_of_g_ = new big_num(6);
    pt384_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[4] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[3] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[2] = 0xc7634d81f4372ddfULL;
    pt384_Key.order_of_g_->value_[1] = 0x581a0db248b0a77aULL;
    pt384_Key.order_of_g_->value_[0] = 0xecec196accc52973ULL;
    pt384_Key.order_of_g_->normalize();

    pt384_Key.g_.x_ = new big_num(6);
    pt384_Key.g_.x_->value_[5] = 0xaa87ca22be8b0537ULL;
    pt384_Key.g_.x_->value_[4] = 0x8eb1c71ef320ad74ULL;
    pt384_Key.g_.x_->value_[3] = 0x6e1d3b628ba79b98ULL;
    pt384_Key.g_.x_->value_[2] = 0x59f741e082542a38ULL;
    pt384_Key.g_.x_->value_[1] = 0x5502f25dbf55296cULL;
    pt384_Key.g_.x_->value_[0] = 0x3a545e3872760ab7ULL;
    pt384_Key.g_.x_->normalize();
    pt384_Key.g_.y_ = new big_num(6);
    pt384_Key.g_.y_->value_[5] = 0x3617de4a96262c6fULL;
    pt384_Key.g_.y_->value_[4] = 0x5d9e98bf9292dc29ULL;
    pt384_Key.g_.y_->value_[3] = 0xf8f41dbd289a147cULL;
    pt384_Key.g_.y_->value_[2] = 0xe9da3113b5f0b8c0ULL;
    pt384_Key.g_.y_->value_[1] = 0x0a60b1ce1d7e819dULL;
    pt384_Key.g_.y_->value_[0] = 0x7a431d7c90ea0e5fULL;
    pt384_Key.g_.y_->normalize();
    pt384_Key.g_.z_ = new big_num(1, 1ULL);

    pt384_Key.g_.z_->normalize();
    pt384_Key.base_.x_ = nullptr;
    pt384_Key.base_.y_ = nullptr;
    pt384_Key.base_.z_ = nullptr;
    pt384_key_valid = true;
    pt384_Key.key_valid_ = true;
  }

  // pt-521
  if (!pt521_key_valid) {

    pt521_Key.c_.modulus_bit_size_ = 521;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt521_Key.key_name_ = new string("pt-521");
    pt521_Key.key_type_ = new string("ecc-521");
    pt521_Key.key_usage_ = new string("all");
    pt521_Key.key_owner_ = new string("NIST");
    pt521_Key.not_before_ = time_now;
    pt521_Key.not_after_ = time_later;

    pt521_Key.c_.p_ = new big_num(9);
    pt521_Key.c_.p_->value_[8] = 0x1ffULL;
    pt521_Key.c_.p_->value_[7] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[6] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[2] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[1] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->normalize();

    pt521_Key.c_.a_ = new big_num(9);
    pt521_Key.c_.a_->value_[8] = 0x0b4ULL;
    pt521_Key.c_.a_->value_[7] = 0x8bfa5f420a349495ULL;
    pt521_Key.c_.a_->value_[6] = 0x39d2bdfc264eeeebULL;
    pt521_Key.c_.a_->value_[5] = 0x077688e44fbf0ad8ULL;
    pt521_Key.c_.a_->value_[4] = 0xf6d0edb37bd6b533ULL;
    pt521_Key.c_.a_->value_[3] = 0x281000518e19f1b9ULL;
    pt521_Key.c_.a_->value_[2] = 0xffbe0fe9ed8a3c22ULL;
    pt521_Key.c_.a_->value_[1] = 0x00b8f875e523868cULL;
    pt521_Key.c_.a_->value_[0] = 0x70c1e5bf55bad637ULL;
    pt521_Key.c_.a_->normalize();

    pt521_Key.c_.b_ = new big_num(9);
    pt521_Key.c_.b_->value_[8] = 0x051ULL;
    pt521_Key.c_.b_->value_[7] = 0x953eb9618e1c9a1fULL;
    pt521_Key.c_.b_->value_[6] = 0x929a21a0b68540eeULL;
    pt521_Key.c_.b_->value_[5] = 0xa2da725b99b315f3ULL;
    pt521_Key.c_.b_->value_[4] = 0xb8b489918ef109e1ULL;
    pt521_Key.c_.b_->value_[3] = 0x56193951ec7e937bULL;
    pt521_Key.c_.b_->value_[2] = 0x1652c0bd3bb1bf07ULL;
    pt521_Key.c_.b_->value_[1] = 0x3573df883d2c34f1ULL;
    pt521_Key.c_.b_->value_[0] = 0xef451fd46b503f00ULL;
    pt521_Key.c_.b_->normalize();

    pt521_Key.bit_size_modulus_ = 521;
    pt521_Key.order_of_g_ = new big_num(9);
    pt521_Key.order_of_g_->value_[8] = 0x01ffULL;
    pt521_Key.order_of_g_->value_[7] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[6] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[4] = 0xfffffffffffffffaULL;
    pt521_Key.order_of_g_->value_[3] = 0x51868783bf2f966bULL;
    pt521_Key.order_of_g_->value_[2] = 0x7fcc0148f709a5d0ULL;
    pt521_Key.order_of_g_->value_[1] = 0x3bb5c9b8899c47aeULL;
    pt521_Key.order_of_g_->value_[0] = 0xbb6fb71e91386409ULL;
    pt521_Key.order_of_g_->normalize();

    pt521_Key.g_.x_ = new big_num(9);
    pt521_Key.g_.x_->value_[8] = 0xc6ULL;
    pt521_Key.g_.x_->value_[7] = 0x858e06b70404e9cdULL;
    pt521_Key.g_.x_->value_[6] = 0x9e3ecb662395b442ULL;
    pt521_Key.g_.x_->value_[5] = 0x9c648139053fb521ULL;
    pt521_Key.g_.x_->value_[4] = 0xf828af606b4d3dbaULL;
    pt521_Key.g_.x_->value_[3] = 0xa14b5e77efe75928ULL;
    pt521_Key.g_.x_->value_[2] = 0xfe1dc127a2ffa8deULL;
    pt521_Key.g_.x_->value_[1] = 0x3348b3c1856a429bULL;
    pt521_Key.g_.x_->value_[0] = 0xf97e7e31c2e5bd66ULL;
    pt521_Key.g_.x_->normalize();
    pt521_Key.g_.y_ = new big_num(9);
 
    pt521_Key.g_.y_->value_[8] = 0x118ULL;
    pt521_Key.g_.y_->value_[7] = 0x39296a789a3bc004ULL;
    pt521_Key.g_.y_->value_[6] = 0x5c8a5fb42c7d1bd9ULL;
    pt521_Key.g_.y_->value_[5] = 0x98f54449579b4468ULL;
    pt521_Key.g_.y_->value_[4] = 0x17afbd17273e662cULL;
    pt521_Key.g_.y_->value_[3] = 0x97ee72995ef42640ULL;
    pt521_Key.g_.y_->value_[2] = 0xc550b9013fad0761ULL;
    pt521_Key.g_.y_->value_[1] = 0x353c7086a272c240ULL;
    pt521_Key.g_.y_->value_[0] = 0x88be94769fd16650ULL;
    pt521_Key.g_.y_->normalize();
    pt521_Key.g_.z_ = new big_num(1, 1ULL);

    pt521_Key.g_.z_->normalize();
    pt521_Key.base_.x_ = nullptr;
    pt521_Key.base_.y_ = nullptr;
    pt521_Key.base_.z_ = nullptr;
    pt521_key_valid = true;
    pt521_Key.key_valid_ = true;
  }

  return true;
}
