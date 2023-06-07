#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/files.h>
#include <crypto++/hex.h>
#include <crypto++/hkdf.h>
#include <crypto++/hmac.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/sha.h>

#include "../../include-shared/messages.hpp"

using namespace CryptoPP;

class CryptoDriver {
public:
  SecByteBlock AES_generate_key(const SecByteBlock &DH_shared_key);
  std::pair<std::string, SecByteBlock> AES_encrypt(SecByteBlock key,
                                                   std::string plaintext);
  std::string AES_decrypt(SecByteBlock key, SecByteBlock iv,
                          std::string ciphertext);

  SecByteBlock HMAC_generate_key(const SecByteBlock &DH_shared_key);
  std::string HMAC_generate(SecByteBlock key, std::string ciphertext);
  bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);

  std::pair<Mat, Mat> GGH_generate();
  SecByteBlock GGH_encrypt(SecByteBlock pk, SecByteBlock m, std::optional<SecByteBlock> r);
  SecByteBlock GGH_decrypt(Mat sk, Mat pk, SecByteBlock e);

  std::string hash(std::string msg);
  void split_hash_three(std::string h, SecByteBlock &i1, SecByteBlock &i2, SecByteBlock &i3);
  std::pair<std::tuple<SecByteBlock, SecByteBlock>, SecByteBlock>
  encaps(SecByteBlock pk);
  SecByteBlock decaps(Mat sk, Mat pk, std::tuple<SecByteBlock, SecByteBlock> c);
};
