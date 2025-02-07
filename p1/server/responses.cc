#include <cassert>
#include <iostream>
#include <string>

#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

using namespace std;
using std::begin, std::end;

//Helper function to extract username, password, and content from the unencrypted ablock in
//order to pass them into the corresponding method in storage.cc
///@param ablock ablock that we received from parsing
vector<string> Extract(vector<uint8_t> ablock){
  //Iterator that points to the ablock
  uint8_t* d = ablock.data();
  //Counter to count which bytes we are in
  size_t counter = 0;
  //Vector of string that we return
  vector<string> info;


  //Get the username's size
  size_t user_size;
  memcpy(&user_size, &ablock[counter], sizeof(size_t));
  //Reset counter after username's size
  counter += 8;
  //Get username
  string user ="";
  vector<uint8_t> user_b;
  for(int i = counter; i < counter + user_size; i++){
    user_b.push_back(*(d+i));
  }
  user.assign(user_b.begin(), user_b.end());
  counter += user_size;


  //Get the password's size
  size_t pass_size;
  memcpy(&pass_size, &ablock[counter], sizeof(size_t));
  counter += 8;
  //Get password
  string pass= "";
  vector<uint8_t> pass_b;
  for(int i = counter; i < counter + pass_size; i++){
    pass_b.push_back(*(d+i));
  }
  pass.assign(pass_b.begin(), pass_b.end());
  counter += pass_size;

  //Push back username and pass
  info.push_back(user);
  info.push_back(pass);

  //Check we have content to read
  if(ablock.size() > counter){
    //Get the content's size
    size_t content_size;
    memcpy(&content_size, &ablock[counter], sizeof(size_t));
    counter += 8;
    //Get the content
    string content= "";
    vector<uint8_t> content_b;
    if(content_size != 0){
      for(int i = counter; i < counter + content_size; i++){
        content_b.push_back(*(d+i));
      }
      content.assign(content_b.begin(), content_b.end());
      info.push_back(content);
    }
  }
  
 
  //Return what we extracted
  
  
  return info;
}



//Helper function to take a vector and put its size into a vector<uint8_t>
  ///@param v vector to get it size
  ///@return a vector contain the size
  vector<uint8_t> size_block(vector<uint8_t> block){
    size_t size = block.size();
    vector<uint8_t> sizeB(sizeof(size));
    memcpy(sizeB.data(), &size, sizeof(size));
    return sizeB;
  }

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);

  //Extract information from req, we just need username and pass
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];
  
  auto aut = storage->auth(user, pass);
  if(!aut.succeeded){
    send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
    return false;
  }

  //Get all username from the table
  auto namelist = storage->get_all_users(user, pass);

  //Check if we get all name
  if(!namelist.succeeded){
    //send back the error messages
    send_reliably(sd, aes_crypt_msg(ctx, namelist.msg));
    return false;
  }

  vector<uint8_t> response;
  
  //Get size of namelist
  vector<uint8_t> data_size = size_block(namelist.data);

  //Prepare out response
  response.insert(end(response), RES_OK.begin(),RES_OK.end() );
  response.insert(end(response), begin(data_size), end(data_size));
  response.insert(end(response), begin(namelist.data), end(namelist.data));

  send_reliably(sd, aes_crypt_msg(ctx, response));
  return false;
   
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);

  

  //Extract information from req
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];
  string content = info[2];

  auto aut = storage->auth(user, pass);
  if(!aut.succeeded){
    send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
    return false;
  }
  
  //Handle too large profile file
  if(content.length() > LEN_PROFILE_FILE){
    send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT ));
  }

  //Create content vector
  vector<uint8_t> contentv;
  contentv.assign(content.begin(), content.end());

  //Set user content to the table
  auto result = storage->set_user_data(user, pass, contentv);
  send_reliably(sd, aes_crypt_msg(ctx, result.msg));


  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  //Extract information from req
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];
  string content = info[2];
  
  auto aut = storage->auth(user, pass);
  if(!aut.succeeded){
    send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
    return false;
  }

  //Get specific username from the table
  auto namelist = storage->get_user_data(user,pass,content);

  
  //Check if we get the name
  
  if(namelist.succeeded == false){
    //send back the error messages
    send_reliably(sd, aes_crypt_msg(ctx, namelist.msg));
    return false;
  }
  
  
  vector<uint8_t> response;
  
  //Get size of namelist
  vector<uint8_t> data_size = size_block(namelist.data);

  //Prepare out response
  response.insert(end(response), begin(namelist.msg),begin(namelist.msg));
  response.insert(end(response), begin(data_size), end(data_size));
  response.insert(end(response), begin(namelist.data), end(namelist.data));

  send_reliably(sd, aes_crypt_msg(ctx, response));
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  //Extract information from req, we just need username and pass
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];
  
  

  //Get all username from the table
  auto namelist = storage->add_user(user, pass);

  //Check if we get all name
  if(namelist.succeeded == false){
    //send back the error messages
    send_reliably(sd, aes_crypt_msg(ctx, namelist.msg));
    return false;
  }

  
  send_reliably(sd, aes_crypt_msg(ctx, namelist.msg));
  return false;
  
  
  }
  
  

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubfile.size() > 0);

  //send pubfile 
  send_reliably(sd, pubfile);

  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  
  //Extract information from req, we just need username and pass
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];

  //Authorize user
  auto aut = storage->auth(user, pass);
  if(!aut.succeeded){
    send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
    return false;
  }

  storage->shutdown();
  send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
  return true;
  
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
 
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  //Extract information from req, we just need username and pass
  vector<string> info = Extract(req);
  string user = info[0];
  string pass = info[1];

  auto aut = storage->auth(user, pass);
  if(!aut.succeeded){
    send_reliably(sd, aes_crypt_msg(ctx, aut.msg));
    return false;
  }

  auto sav = storage->save_file();
  send_reliably(sd, aes_crypt_msg(ctx, sav.msg));
  return false;

}
