#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Generates AES key using HKDR with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for AES using the provided
 * salt. See the `DeriveKey` function. (Use NULL for the "info" argument)
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // TODO: implement me!
  SecByteBlock aes_key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(aes_key, aes_key.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);
  return aes_key;
}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size AES::BLOCKSIZE
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * `AES_encryptor`.
 * 3) Return ciphertext and iv used in encryption or throw a
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // TODO: implement me!
    AutoSeededRandomPool prng;
    SecByteBlock iv(AES::BLOCKSIZE);

    CBC_Mode<AES>::Encryption enc;
    enc.GetNextIV(prng, iv);
    enc.SetKeyWithIV(key, key.size(), iv);
    std::string ciphertext;
    StringSource s(plaintext, true, 
          new StreamTransformationFilter(enc,
              new StringSink(ciphertext)
          ) // StreamTransformationFilter
      ); // StringSource
      return std::make_pair(ciphertext, iv);

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using SetKeyWithIV on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using `AES_decryptor`.
 * 3) Return the plaintext or throw a `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    // TODO: implement me!
    CBC_Mode<AES>::Decryption dec;
    std::string plaintext;

    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(dec,
            new StringSink(plaintext)
        ) // StreamTransformationFilter
    ); // StringSource
    return plaintext;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!
  SecByteBlock hmac_key(SHA256::BLOCKSIZE);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(hmac_key, hmac_key.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);
  return hmac_key;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    // TODO: implement me!
    HMAC<SHA256> hmac(key, key.size());
    std::string mac;
    StringSource ss2(ciphertext, true, 
        new HashFilter(hmac,
            new StringSink(mac)
        ) // HashFilter      
    ); // StringSource
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the message through a `HashVerificationFilter` to verify the HMAC.
 * 3) Return false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  // TODO: implement me!
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true, 
          new HashVerificationFilter(hmac, NULL, flags)
      ); // StringSource
    return true;
  } catch (const CryptoPP::Exception &e) {
    return false;
  }
}

/**
 * @brief generate GGH public and private keys
 */
std::pair<Mat, Mat> CryptoDriver::GGH_generate() {
  GGHDriver ggh;
  std::pair<Mat, Mat> keys = ggh.generate();
  return keys;
}

/**
 * @brief encrypt a message using GGH
 */
SecByteBlock CryptoDriver::GGH_encrypt(SecByteBlock pk, SecByteBlock m, std::optional<SecByteBlock> r) {
  // use SecByteBlocks here because the pk, m, and r might come from the other party
  GGHDriver ggh;
  Mat pk_m = ggh.copy_to_mat(pk);
  Mat m_v = ggh.byteblock_to_msg(m);
  std::optional<Mat> r_v;
  if (r.has_value()) {
    r_v = std::optional<Mat>{ggh.byteblock_to_msg(r.value())};
  } else {
    r_v = std::optional<Mat>{};
  }
  Mat e = ggh.encrypt(pk_m, m_v, r_v);
  return ggh.copy_to_block(e);
}

/**
 * @brief decrypt a ciphertext using GGH
 */
SecByteBlock CryptoDriver::GGH_decrypt(Mat sk, Mat pk, SecByteBlock e) {
  // use Mats here because we generated the keys locally, but e came from the other party
  GGHDriver ggh;
  Mat e_v = ggh.copy_to_mat(e);
  Mat m = ggh.decrypt(sk, pk, e_v);
  return ggh.msg_to_byteblock(m, 256/8);
}

/**
 * @brief Generates a SHA-256 hash of msg.
 */
std::string CryptoDriver::hash(std::string msg) {
  SHA256 hash;
  std::string encodedHex;
  HexEncoder encoder(new StringSink(encodedHex));

  // Compute hash
  StringSource(msg, true, new HashFilter(hash, new StringSink(encodedHex)));
  return encodedHex;
}

// Kyber implementation modified to work with ElGamal
// from https://cryptosith.org/papers/kyber-20170627.pdf

void CryptoDriver::split_hash_three(std::string h, SecByteBlock &i1, SecByteBlock &i2, SecByteBlock &i3) {
  int sublen = h.length()/3;
  i1 = string_to_byteblock(h.substr(0, sublen));
  i2 = string_to_byteblock(h.substr(sublen, sublen*2));
  i2 = string_to_byteblock(h.substr(sublen*2, sublen*3));
}

std::pair<std::tuple<SecByteBlock, SecByteBlock>, SecByteBlock>
CryptoDriver::encaps(SecByteBlock pk) {
  AutoSeededRandomPool rng;
  SecByteBlock m_bytes(256/8); // 256 bits
  rng.GenerateBlock(m_bytes, m_bytes.size());
  std::string m_str = byteblock_to_string(m_bytes);
  std::string pk_str = byteblock_to_string(pk);
  std::string Khrd = hash(pk_str + m_str); // 256 bits
  SecByteBlock K_hat;
  SecByteBlock r;
  SecByteBlock d;
  split_hash_three(Khrd, K_hat, r, d);
  std::string K_hat_str = byteblock_to_string(K_hat);
  auto uv = GGH_encrypt(pk, m_bytes, std::optional<SecByteBlock>{r});
  uv = GGH_encrypt(pk, m_bytes, std::optional<SecByteBlock>{r});
  auto c = std::make_tuple(uv, d);
  std::string c_str = byteblock_to_string(std::get<0>(c)) +
                      byteblock_to_string(std::get<1>(c));
  std::string K_str = hash(K_hat_str + c_str);
  SecByteBlock K = string_to_byteblock(K_str);
  return std::make_pair(c, K);
}

SecByteBlock CryptoDriver::decaps(Mat sk, Mat pk,
                                  std::tuple<SecByteBlock, SecByteBlock> c) {
  SecByteBlock m_bytes = GGH_decrypt(sk, pk, std::get<0>(c));
  GGHDriver ggh;
  SecByteBlock pkb = ggh.copy_to_block(pk);
  std::string m_str = byteblock_to_string(m_bytes);
  std::string pk_str = byteblock_to_string(pkb);
  std::string Khrd = hash(pk_str + m_str); // 256 bits
  SecByteBlock K_hat;
  SecByteBlock r;
  SecByteBlock d;
  split_hash_three(Khrd, K_hat, r, d);
  std::string K_hat_str = byteblock_to_string(K_hat);
  auto uv = GGH_encrypt(pkb, m_bytes, std::optional<SecByteBlock>{r});
  uv = GGH_encrypt(pkb, m_bytes, std::optional<SecByteBlock>{r});
  std::string c_str = byteblock_to_string(std::get<0>(c)) +
                      byteblock_to_string(std::get<1>(c));
  std::string K_str;
  if (uv == std::get<0>(c) && d == std::get<1>(c)) {
    K_str = hash(K_hat_str + c_str);
  } else {
    // z is a random secret seed
    std::string z_str = byteblock_to_string(ggh.copy_to_block(sk));
    // return pseudo-random key
    K_str = hash(z_str + c_str);
  }
  SecByteBlock K = string_to_byteblock(K_str);
  return K;
}