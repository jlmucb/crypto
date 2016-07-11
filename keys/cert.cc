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
// File: cert.cc

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <string>
#include <iostream>
#include <type_traits>
#include <fstream>

#include "cryptotypes.h"
#include "conversions.h"
#include "util.h"
#include "keys.h"
#include "keys.pb.h"
#include "cert.pb.h"
#include "cert.h"

proto_cert::proto_cert() {
  /*
  string version_;
  name subject_name_[]; 
  string signature_algorithm_;
  string purpose_;
  property properties_[];
  string not_before_;
  string not_after_;
  string nonce_;
  string canonical_;
  string revocation_address_;
  string date_signed_;
  name issuer_name_[]; 
  string signature_;
   */
}

proto_cert::~proto_cert() {
}

bool proto_cert::FillProto(certificate_message* cert) {
}

bool proto_cert::FillSignerParameter() {
}

bool proto_cert::FillSignature(int size, byte* sig) {
}

bool proto_cert::ReadFromProto(certificate_message& cert) {
}

string& proto_cert::getVersion() {
}

string& proto_cert::getPurpose() {
}

string& proto_cert::getNotBefore() {
}

string& proto_cert::getNotAfter() {
}

string& proto_cert::getSignature() {
}

string& proto_cert::getNonce() {
}

string& proto_cert::getCanonical() {
}

string& proto_cert::getDateSigned() {
}

void proto_cert::putVersion() {
}

void proto_cert::putPurpose() {
}

void proto_cert::putNotBefore() {
}

void proto_cert::putNotAfter() {
}

void proto_cert::putSignature() {
}

void proto_cert::putNonce() {
}

void proto_cert::putCanonical() {
}

void proto_cert::putDateSigned() {
}

void PrintProto(certificate_message& cert) {
}

void ComputeCanonical(certificate_message* cert) {
}

