#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Uses a Kyber shared secret to replace the keys.
 */
void Client::prepare_keys(CryptoPP::SecByteBlock K) {
  // K is the shared secret from the Kyber protocol
  this->AES_key = this->crypto_driver->AES_generate_key(K);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(K);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Encrypt and tag the message. (Ratchet is disabled for now.)
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // TODO: implement me!
  Message_Message msg;

  std::pair<std::string, SecByteBlock> c_iv = this->crypto_driver->AES_encrypt(this->AES_key, plaintext);
  
  msg.iv = std::get<1>(c_iv);
  msg.ciphertext = std::get<0>(c_iv);
  msg.mac = this->crypto_driver->HMAC_generate(this->HMAC_key, concat_msg_fields(msg.iv, msg.ciphertext));
  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Decrypt and verify the message. (Ratchet is disabled for now.)
 */
std::pair<std::string, bool> Client::receive(Message_Message ciphertext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  return std::make_pair<std::string, bool>(this->crypto_driver->AES_decrypt(this->AES_key, ciphertext.iv, ciphertext.ciphertext), this->crypto_driver->HMAC_verify(this->HMAC_key, concat_msg_fields(ciphertext.iv, ciphertext.ciphertext), ciphertext.mac));
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send a public key depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for the public key, and the connecter should generate and send the public
 * key. The connector is P1 in the Kyber protocol while the listener is P2.
 * 2) For the listener: listen for the other party's public value and encapsulate it.
 * Send the encapsulated key to the other party.
 * 3) For the connector: receive the encapsualted key from the other party and
 * decapsulate it.
 * 4) Both parties now use their shared secret to prepare AES and HMAC keys
 * using the `prepare_keys` function.
 */
void Client::HandleKeyExchange(std::string command) {
  // TODO: implement me!

  if (command == "connect") {
    // P1
    auto keys = this->crypto_driver->GGH_generate();
    auto sk = keys.first;
    auto pk = keys.second;

    GGHDriver ggh;
    PublicValue_Message pvm;
    pvm.public_value = ggh.copy_to_block(pk);
    std::vector<unsigned char> pkey_to_send;
    pvm.serialize(pkey_to_send);

    this->network_driver->send(pkey_to_send);


    // P1 again
    Encapsulation_Message em;
    std::vector<unsigned char> c_to_get = this->network_driver->read();
    em.deserialize(c_to_get);

    auto c = std::make_tuple(em.uv, em.d);
    auto K = this->crypto_driver->decaps(sk, pk, c);

    //std::cout << "P1 K " << byteblock_to_string(K) << std::endl;
    this->prepare_keys(K);
  } else if (command == "listen") {
    // P2
    PublicValue_Message pvm;
    std::vector<unsigned char> other_pkey = this->network_driver->read();
    pvm.deserialize(other_pkey);

    auto encaps = this->crypto_driver->encaps(pvm.public_value);
    auto c = encaps.first;
    auto K = encaps.second;

    Encapsulation_Message em;
    em.uv = std::get<0>(c);
    em.d = std::get<1>(c);
    std::vector<unsigned char> c_to_send;
    em.serialize(c_to_send);

    this->network_driver->send(c_to_send);

    //std::cout << "P2 K " << byteblock_to_string(K) << std::endl;
    this->prepare_keys(K);
  }
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}