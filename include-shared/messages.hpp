#pragma once

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>

#include "../include/drivers/ggh_driver.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  DHParams_Message = 0,
  PublicValue = 1,
  Message = 2,
  Encapsulation = 3,
};
}
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// Serializers.
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// Deserializers.
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// MESSAGES
// ================================================

struct DHParams_Message : public Serializable {
  CryptoPP::Integer p;
  CryptoPP::Integer q;
  CryptoPP::Integer g;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct PublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Message_Message : public Serializable {
  CryptoPP::SecByteBlock iv;
  // CryptoPP::SecByteBlock public_value;
  std::string ciphertext;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KYBER KEY ENCAPSULATION MESSAGES
// from https://cryptosith.org/papers/kyber-20170627.pdf page 6
// ================================================

/**
 * 1) P1 sends PublicValue_Message
 * 2) P2 encapsulates pk and sends Encapsulation_Message
 * 3) P3 decapsulates c using sk. This does not require a new message
 */

struct Encapsulation_Message : public Serializable {
  // In Kyber, c is a tuple containing (u, v, d)
  CryptoPP::SecByteBlock uv;
  CryptoPP::SecByteBlock d;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};