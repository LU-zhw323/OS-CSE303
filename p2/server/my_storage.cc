#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <mutex>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/file.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"


using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  //Helper function to take a vector and put its size into a vector<uint8_t>
  ///@param v vector to get it size
  ///@return a vector contain the size
  vector<uint8_t> size_block(vector<uint8_t> block){
    size_t size = block.size();
    vector<uint8_t> sizeB(sizeof(size));
    memcpy(sizeB.data(), &size, sizeof(size));
    return sizeB;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    //Create a authetable of username and pass word
    AuthTableEntry newUser;
    newUser.username = user;
    //Generate salt
    unsigned char* buf;
    vector<uint8_t> salt(LEN_SALT);
    RAND_bytes(salt.data(), LEN_SALT);
      
    //Add salt to authetable
    newUser.salt = salt;
    //Gnerate pass block
    vector<uint8_t> Pass;
    Pass.assign(begin(pass), end(pass));
    //Add salt block and pass block
    vector<uint8_t> spblock;
    spblock.insert(end(spblock), begin(Pass), end(Pass));
    spblock.insert(end(spblock), begin(salt), end(salt));
    
    //Apply SHA_256 hashing, retrieved from https://qa.1r1g.com/sf/ask/964910411/
    vector<uint8_t> hashPass(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, spblock.data(), spblock.size());
    SHA256_Final(hashPass.data(), &sha256);
    //Add hashpass
    newUser.pass_hash = hashPass;
    //Add content
    newUser.content = {};
    //Function on success
    std::function<void()> onsuccess = [](){};
    //Insert newUser into table
    bool result = auth_table->insert(user, newUser, onsuccess);
    if(!result){
      return {false, RES_ERR_USER_EXISTS, {}};
    }
    return {true, RES_OK, {}};
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
    
    //Define function to update content
    std::function<void(AuthTableEntry &)> f = [&](AuthTableEntry entry){
      entry.content = content;
      auth_table->upsert(user, entry, [](){}, [](){});
    };
    //Create a authetable of username and pass word
    bool result = auth_table->do_with(user, f);
    if(!result){
      return {false, RES_ERR_SERVER, {}};
    }
    else{
      return {true, RES_OK, {}};
    }
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(who.length() > 0);
    //Define the function to fetch content
    vector<uint8_t> content;
    std::function<void(AuthTableEntry &)> f = [&](AuthTableEntry entry){
      content.insert(end(content), entry.content.begin(), entry.content.end());
    };
    bool result = auth_table->do_with(who, f);
    if(!result){
      return {false, RES_ERR_NO_USER, {}};
    }
    else{
      if(content.begin() == content.end()){
        return {false, RES_ERR_NO_DATA, content};
      }
      else{
        return {true, RES_OK, content};
      }
    }
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    
    //string names;
    vector<uint8_t> names;
    std::function<void(const string, const AuthTableEntry &)> f = [&](string name, AuthTableEntry){
      names.insert(end(names), name.begin(), name.end());
      names.push_back('\n');
    };

    auth_table->do_all_readonly(f, [](){});
    return{true, RES_OK,names};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    bool auth = true;
    //Define a function(lambada) to do the authenticate
    std::function<void(const AuthTableEntry &)> f = [&](AuthTableEntry entry){
      //Get the password with salt in entry, cause salt will be used to authenticate
      vector<uint8_t> newPass;
      newPass.insert(end(newPass), begin(pass), end(pass));
      newPass.insert(end(newPass), begin(entry.salt), end(entry.salt));

      vector<uint8_t> newPass_hash(LEN_PASSHASH);
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, newPass.data(), newPass.size());
      SHA256_Final(newPass_hash.data(), &sha256);
      //Check if the pass_hash in table is same as the input pass_hash
      if(newPass_hash != entry.pass_hash){
        //Since [&] will capture all variable, we can use it to assign auth
        auth = false;
      }
    };
    bool result = auth_table->do_with_readonly(user, f);
    //Check if we have this user
    if(result == false){
      return{false, RES_ERR_LOGIN, {}};
    }
    else{//check if the password is correct
      if(auth == false){
        return{false, RES_ERR_LOGIN, {}};
      }
      else{
        return{true, RES_OK, {}};
      }
    }
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
    //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Insert key/value
    bool result = kv_store->insert(key,val, [](){});
    if(!result){
      return{false, RES_ERR_KEY, {}};
    }
    else{
      return{true, RES_OK, {}};
    }
    return{false, RES_ERR_SERVER, {}};

  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
   //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Get key/value from the kvstore
    vector<uint8_t> info;
    std::function<void(const vector<uint8_t> &)> f = [&](vector<uint8_t> val){
      info.insert(end(info), begin(val), end(val));
    };
    bool result = kv_store->do_with(key, f);
    if(result){
      return {true, RES_OK, info};
    }
    else{
      return {false, RES_ERR_KEY, {}};
    }
    return{false, RES_ERR_SERVER, {}};

  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    bool result = kv_store->remove(key, [](){});
    if(result){
      return{true, RES_OK, {}};
    }
    else{
      return{false, RES_ERR_KEY, {}};
    }
    return{false, RES_ERR_SERVER, {}};
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    bool result = kv_store->upsert(key, [](){}, [](){});
    if(result){
      return{true, RES_OKINS, {}};
    }
    else{
      return{true, RES_OKUPD, {}};
    }
    return{false, RES_ERR_SERVER, {}};
    
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    cout << "my_storage.cc::kv_all() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    string x = "\n";
    vector<uint8_t> linebreak;
    linebreak.assign(begin(x), end(x));
    vector<uint8_t> info;
    std::function<void(const string, const vector<uint8_t> &)> f = [&](string key, vector<uint8_t> val){
      info.insert(end(info), begin(key), end(key));
      info.insert(end(info), begin(linebreak), end(linebreak));
    };
    kv_store->do_all_readonly(f, [](){});
    if(info.empty()){
      return {false, RES_ERR_NO_DATA, {}};
    }
    else{
      return {true, RES_OK, info};
    }
    return {false, RES_ERR_SERVER, {}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    auth_table->clear();
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    cout << "my_storage.cc::save_file() is not implemented\n";
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    
    //clear auth_table
    auth_table->clear();
    kv_store->clear();
    
    //read the content of the file
    vector<uint8_t> load = load_entire_file(this->filename);
    
    //Counter to record the position;
    size_t counter = 0;
    //boolean to findout what we should load
    bool onAuth = false;
    bool onKV = false;
    //Start looping and read information, each loop corresponding to one user
    //Since length of username, password, salt, content are unknown, for loop won't help
    while(counter<load.size()){
      //Pointer of file vector
      uint8_t* d = load.data();
      //Determine the first 8 byte
      vector<uint8_t> tag;
      for(int i = counter; i< counter+8; i++){
        tag.push_back(*(d+i));
      }
      string Tag;
      Tag.assign(tag.begin(), tag.end());



    }
    return {true, "Loaded: "+filename, {}};
  };
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
