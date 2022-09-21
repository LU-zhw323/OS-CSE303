#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;
using std::begin, std::end;

/// Helper method to check if the provided block of data is a kblock
///
/// @param block The block of data
///
/// @returns true if it is a kblock, false otherwise
bool is_kblock(vector<uint8_t> &block){
  uint8_t* d = block.data();
  vector<uint8_t> kblock;
  for(int i = 0; i < 8; i++){
    kblock.push_back(*(d+i));
  }
  string keyword;
  keyword.assign(begin(kblock), end(kblock));
  //See if the request is REQ_KEY
  if(keyword==REQ_KEY){
    return true;
  }
  return false;
}


/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  // NB: These assertions are only here to prevent compiler warnings
  assert(pri);
  assert(storage);
  assert(pub.size() > 0);
  assert(sd);
  
  //vector<uint8_t> msg = reliable_get_to_eof(sd);
  //Get request from server
  vector<uint8_t> rk_block(LEN_RKBLOCK);
  reliable_get_to_eof_or_n(sd, rk_block.begin(), (int)LEN_RKBLOCK);
  
  
  /*
  vector<uint8_t> rk_block(LEN_RKBLOCK);
  uint8_t* mp = msg.data();
  for(int i = 0; i < LEN_RKBLOCK; i++){
    rk_block.push_back(*(mp+i));
  }
  */

  //Handle kblock
  bool key = is_kblock(rk_block);
  if(key){
    return handle_key(sd, pub);
  }


  //Handle rblock
  vector<uint8_t> rblock(RSA_size(pri));
  //Use private key to decrypt
  RSA_private_decrypt(rk_block.size(), rk_block.data(), rblock.data(), pri, RSA_PKCS1_OAEP_PADDING);
  uint8_t* d = rblock.data();
  size_t counter = 0;
  //Pull cmd from the rblock, first 8 bytes
  vector<uint8_t> cblock;
  string cmd;
  counter += 8;
  for(int i = 0; i < counter; i++){
    cblock.push_back(*(d+i));
  }
  cmd.assign(cblock.begin(), cblock.end());
  
  //create the vector to store aes key
  vector<uint8_t> aeskey;
  for(int i = counter; i < AES_KEYSIZE+AES_IVSIZE+counter; i++){
    aeskey.push_back(*(d+i));
  }
  counter += AES_KEYSIZE;
  counter += AES_IVSIZE;
  
  //get and store the length of ablock
  size_t ablock_size;
  memcpy(&ablock_size, &rblock[counter], sizeof(size_t));
  
  //read and store ablock
  vector<uint8_t> ablock(ablock_size);
  reliable_get_to_eof_or_n(sd, ablock.begin(), (int)ablock_size);
  /*
  for(int i = (int)LEN_RKBLOCK; i < msg.size(); i++){
    ablock.push_back(*(mp+i));
  }
  */
  //Generate AES key
  EVP_CIPHER_CTX *ctx = create_aes_context(aeskey, false);
  //Dectypt ablock and check the result
  vector<uint8_t> ori_ablock;
  ori_ablock = aes_crypt_msg(ctx, ablock);
  if(ori_ablock.size() == 0){
    send_reliably(sd, RES_ERR_CRYPTO);
    return false;
  }
  reset_aes_context(ctx, aeskey, true);

  //handle the request
  //Get the request list
  vector<string> req = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  //Apply method mentioned in README.md
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};
  //Call corresponding handle method by passing request, ctx content, and unencrypt ablock
  for (size_t i = 0; i < req.size(); i++)
    if (cmd == req[i])
      return cmds[i](sd, storage, ctx, ori_ablock);
  //cannot find the cmd required
  send_reliably(sd, RES_ERR_INV_CMD);
  return false;





}




