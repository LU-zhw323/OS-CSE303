#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"

using namespace std;

//Below is some helper function
/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(vector<uint8_t> &v, size_t sz){
  /// @param counter count how many bytes we need to pad in
  size_t counter = v.size();
  while(counter < sz){
    try{
      //pushback a random characters to the vec
      v.push_back(rand()%26);
    }
    catch(std::bad_alloc& ba){
      return false;
    }
    counter += 1;
  }
  return true;
}



/// Check if the provided result vector is a string representation of __OK__
///
/// @param v The vector being compared to RES_OK
///
/// @returns true if the vector contents are RES_OK, false otherwise
bool check_OK(const vector<uint8_t> &v){
  std::string content = RES_OK;
  vector<uint8_t> Okey;
  Okey.insert(Okey.end(), content.begin(), content.end());
  for(int i = 0; i < RES_OK.length(); i++){
    if(Okey.at(i) != v.at(i)){
      return false;
    }
  }
  return true;
}


/// If a buffer consists of OKbbbbd+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vector<uint8_t> &buf, const string &filename){
  size_t size_buf = buf.size();
  //sd 4 bytes + __OK__ 8 bytes + 4 bytes binary integer = 16 bytes
  if(size_buf > 16){
    write_file(filename, buf, 16);
  }
}
/// Create unencrypted ablock contents from one strings
///
/// @param s The string
///
/// @return A vec representing the two strings

vector<uint8_t> ablock_s(const string &s){
  size_t s_length = s.length();
  vector<uint8_t>u_ablock;
  //For the reason that we can't insert a 4 bytes size_t into a vector of uint8_t
  //We need to first assign the length to a same type of vector
  vector<uint8_t> s_len_block(sizeof(s_length));
  memcpy(s_len_block.data(), &s_length, sizeof(s_length));
  //We want length is before the string
  u_ablock.insert(u_ablock.end(), s_len_block.begin(), s_len_block.end());
  u_ablock.insert(u_ablock.end(), s.begin(),s.end());
  return u_ablock;
}

/// Create unencrypted ablock contents from two strings
///
/// @param s1 The first string
/// @param s2 The second string
///
/// @return A vec representing the two strings
vector<uint8_t> ablock_ss(const string &s1, const string &s2){
  vector<uint8_t> s1_ablock = ablock_s(s1);
  vector<uint8_t> s2_ablock = ablock_s(s2);
  vector<uint8_t> u_ablock;
  u_ablock.insert(u_ablock.end(), s1_ablock.begin(), s1_ablock.end());
  u_ablock.insert(u_ablock.end(), s2_ablock.begin(), s2_ablock.end());
  return u_ablock;
}


/// Pad a vec with 0 to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool pad0(vector<uint8_t> &v, size_t sz){
  /// counter counts how many bytes we need to pad in
  size_t counter = v.size();
  while(counter < sz){
    try{
      //pushback a random characters to the vec
      v.push_back(0);
    }
    catch(std::bad_alloc& ba){
      return false;
    }
    counter += 1;
  }
  return true;
}

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vector<uint8_t> send_cmd(int sd, RSA *pub, const string &cmd, const vector<uint8_t> &msg){
  //Apply the helper function in crypto.h to generate aes key
  vector<uint8_t> aes_key = create_aes_key();
  //Generate aes context to do encript/decript
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key,true);
  //Encript ablock
  vector<uint8_t> ablock = aes_crypt_msg(ctx,msg);

  //Get ready to use public key to encrypt rblock
  vector<uint8_t> pre_rblock;
  //Insert cmd, aeskey, length of ablock
  pre_rblock.insert(pre_rblock.end(), cmd.begin(), cmd.end());
  pre_rblock.insert(pre_rblock.end(), aes_key.begin(), aes_key.end());
  size_t size_ablock = ablock.size();
  vector<uint8_t> len_ablock(sizeof(size_ablock));
  memcpy(len_ablock.data(), &size_ablock, sizeof(size_ablock));
  pre_rblock.insert(pre_rblock.end(), len_ablock.begin(), len_ablock.end());
  
  //pad random variable til it fit the size of rblock
  padR(pre_rblock, LEN_RBLOCK_CONTENT);

  //Encrypt rblock by public key
  vector<uint8_t> rblock(RSA_size(pub));
  RSA_public_encrypt(LEN_RBLOCK_CONTENT, pre_rblock.data(), rblock.data(), pub, RSA_PKCS1_OAEP_PADDING);

  //Send both rblock and ablock to the server
  send_reliably(sd, rblock);
  send_reliably(sd, ablock);


  //Reciving respond from server and decrypt it
  vector<uint8_t> receive = reliable_get_to_eof(sd);
  //Generate the decrypt key
  reset_aes_context(ctx, aes_key, false);
  vector<uint8_t> response = aes_crypt_msg(ctx, receive);
  //reclaim memory
  reclaim_aes_context(ctx);
  return response;

}





/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(keyfile.length() > 0);

  //Insert request message into a vector
  vector<uint8_t> k_block;
  std::string req = REQ_KEY;
  k_block.insert(k_block.end(),req.begin(),req.end());
  pad0(k_block,LEN_RKBLOCK);

  //send and recive key
  send_reliably(sd, k_block);
  vector<uint8_t> key = reliable_get_to_eof(sd);
  write_file(keyfile, key, 0);
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  //From a ablock with unencypt message(user+password)
  vector<uint8_t> msg = ablock_ss(user, pass);
  const std::string cmd = REQ_REG;
  //call sendcmd to send message and return result
  vector<uint8_t> response = send_cmd(sd, pubkey, cmd, msg);
  //check response
  /*
  const std::string content;
  content.assign(response.begin(), response.end());
  if(content.compare(RES_OK) == 0){
    cout << RES_OK;
  }
  */
 if(check_OK(response) == true){
  cout << RES_OK;
 }


}


/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);

  //send cmd to server
  vector<uint8_t> msg = ablock_ss(user,pass);
  auto response = send_cmd(sd, pubkey, REQ_BYE, msg);
  if(check_OK(response) == true){
    cout << RES_OK;
  }



}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  //send cmd to server
  vector<uint8_t> msg = ablock_ss(user,pass);
  auto response = send_cmd(sd, pubkey, REQ_SAV, msg);
  if(check_OK(response) == true){
    cout << RES_OK;
  }
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(setfile.length() > 0);
  //Load entire file of setfile->File block
  vector<uint8_t> File = load_entire_file(setfile);
  //Take the size of file->Size block
  size_t file_s = File.size();
  vector<uint8_t> Size (sizeof(File.size()));
  memcpy(Size.data(), &file_s, sizeof(File.size()));
  //Combine 2 block to a entrie file_block
  vector<uint8_t> file_block = ablock_ss(user, pass);
  file_block.insert(file_block.end(), Size.begin(), Size.end());
  file_block.insert(file_block.end(), File.begin(), File.end());

  auto response = send_cmd(sd,pubkey, REQ_SET, file_block);
  if(check_OK(response) == true){
    cout << RES_OK;
  }
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(getname.length() > 0);

  //Create a vector containing user, user length, pass, pass length, getname, get name length
  vector<uint8_t> msg = ablock_ss(user, pass);
  vector<uint8_t> temp = ablock_s(getname);
  msg.insert(msg.end(), temp.begin(), temp.end());

  auto response = send_cmd(sd, pubkey, REQ_GET, msg);
  //Send response to file
  if(check_OK(response) == true){
    cout << RES_OK;
    send_result_to_file(response, getname + ".file.dat");
  }
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);

  vector<uint8_t> msg = ablock_ss(user,pass);
  auto response = send_cmd(sd, pubkey, REQ_ALL, msg);
  if(check_OK(response) == true){
    cout << RES_OK;
    send_result_to_file(response, allfile);
  }

}
