#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

#include "err.h"

#include "protocol.h"
using namespace std;
using std::begin, std::end;

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt
/// @param count length of msg
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start,
                              int count) {
  

  // These asserts are just for preventing compiler warnings:
  assert(ctx);
  assert(start);
  assert(count != -100);

  // figure out the block size that AES is going to use
  
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));

  //vector to return
  vector<uint8_t> encry_msg;
  
  // Set up a buffer where AES puts crypted bits. 
  //The output buffer length should at least be EVP_CIPHER_block_size() byte longer then the input length
  unsigned char out_buf[LEN_PROFILE_FILE + cipher_block_size];
  int out_len;
  
  // crypt msg into out_buf
  if (!EVP_CipherUpdate(ctx, out_buf, &out_len, start, count)) {
    fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
          ERR_error_string(ERR_get_error(), nullptr));
    return {};
  }
  encry_msg.insert(end(encry_msg), out_buf, out_buf + out_len);
  
    
  // crypt the last block
  if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
  fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
          ERR_error_string(ERR_get_error(), nullptr));
  return {};
}
  encry_msg.insert(end(encry_msg), out_buf, out_buf + out_len);


  return encry_msg;
}
