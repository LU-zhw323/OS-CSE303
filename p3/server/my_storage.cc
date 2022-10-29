#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
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
#include "persist.h"
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

  /// The file that we store
  FILE *log = nullptr;

//mutex that are used to lock the read&write process in save_file()
private:
  mutex lock_read; //mutex to lock read
  mutex lock_operation; //mutex to lock any operation that make changes
  mutex lock_write; //mutex to lock write

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
    //Lock operation
    const lock_guard<mutex> guard_operation(lock_operation);
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Write insertion log when insert
    std::function<void()> on_ins = [&](){
      vector<uint8_t> res = log_kvblock(KVENTRY, key, val);
      const std::lock_guard<mutex> guard_write(lock_write);
      //write to the open bucket
        fwrite(res.data(),res.size(),1,log);
        fflush(log);
        fsync(fileno(log));
    };
    //Write update log when update
    std::function<void()> on_upt = [&](){
      vector<uint8_t> res = log_kvblock(KVUPDATE, key, val);
      const std::lock_guard<mutex> guard_write(lock_write);
      //write to the open bucket
        fwrite(res.data(),res.size(),1,log);
        fflush(log);
        fsync(fileno(log));
    };
    bool result = kv_store->upsert(key, val, on_ins, on_upt);
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
    const lock_guard<mutex> guard_operation(lock_operation);
    fclose(log);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    const char* f_name = (filename + ".tmp").c_str();
    //Open a file with above file name and open it as a binary file in write mode
    //Lock before we read the file
    const lock_guard<mutex> guard_operation(lock_operation);
    //Switch mode
    fclose(log);
    log = fopen(f_name,"wb");
    //Define a function to read and write all username in auth_table
    std::function<void(const string, const AuthTableEntry &)> sav_auth = [&](string, AuthTableEntry entry){
      vector<uint8_t> info;
      //According to format, we need AUTHNTRY before anything
      info.insert(end(info), AUTHENTRY.begin(), AUTHENTRY.end());

      //Get size of user, put them into the info
      vector<uint8_t> user(sizeof(entry.username));
      user.assign(entry.username.begin(), entry.username.end());
      vector<uint8_t> user_s = size_block(user);
      info.insert(end(info), begin(user_s), end(user_s));
      info.insert(end(info), begin(entry.username), end(entry.username));


      //Get the size of salt, put them into info
      vector<uint8_t> salt_size;
      salt_size = size_block(entry.salt);
      info.insert(end(info), begin(salt_size), end(salt_size));
      info.insert(end(info), begin(entry.salt), end(entry.salt));

      //Get Hasspass
      vector<uint8_t> pass_s;
      pass_s = size_block(entry.pass_hash);
      info.insert(end(info), begin(pass_s), end(pass_s));
      info.insert(end(info), begin(entry.pass_hash), end(entry.pass_hash));

      //Get content
      vector<uint8_t> content_s;
      content_s = size_block(entry.content);
      info.insert(end(info), begin(content_s), end(content_s));
      if(content_s.size() > 0){
        info.insert(end(info), begin(entry.content), end(entry.content));
      }

      //Binary write of some bytes of padding, to ensure that the next entry will  be aligned on an 8-byte boundary.
      while(info.size( )% 8 != 0){
        info.push_back('\0');
      }
      //Write the vector
      //Since do_all_readonly will lock the entire bucket, we do not need to worry about the 
      //content we read from, but we still need to lock the fwrite to ensure the content in save file
      const lock_guard<mutex> guard(lock_write);
      fwrite(info.data(), info.size(), 1, log); //lock guard unlock after fwrite
    };
    auth_table->do_all_readonly(sav_auth, [](){});



    //Define a function to read and write all username in kvstore
    std::function<void(const string, const vector<uint8_t> &)> sav_kv = [&](string key, vector<uint8_t> val){
      vector<uint8_t> info;
      //According to format, we need KVENTRY before anything
      info.insert(end(info), KVENTRY.begin(), KVENTRY.end());
      //Size and content of key
      vector<uint8_t> key_block(sizeof(key));
      key_block.assign(key.begin(), key.end());
      vector<uint8_t> key_s = size_block(key_block);
      info.insert(end(info), begin(key_s), end(key_s));
      info.insert(end(info), begin(key_block),end(key_block));
      //Size and content of value
      vector<uint8_t> val_s = size_block(val);
      info.insert(end(info), begin(val_s), end(val_s));
      info.insert(end(info), begin(val), end(val));
      //Binary write of some bytes of padding, to ensure that the next entry will  be aligned on an 8-byte boundary.
      while(info.size( )% 8 != 0){
        info.push_back('\0');
      }
      //Write the vector
      //Since do_all_readonly will lock the entire bucket, we do not need to worry about the 
      //content we read from, but we still need to lock the fwrite to ensure the content in save file
      const lock_guard<mutex> guard(lock_write);
      fwrite(info.data(), info.size(), 1, log); //lock guard unlock after fwrite
    };
    kv_store->do_all_readonly(sav_kv,[](){});
    fclose(log);
    //replace the old file with the new one
    rename((this->filename+".tmp").c_str(),this->filename.c_str());
    log = fopen(filename.c_str(), "ab");
    return {true, RES_OK, {}};//lock guard unlock
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    const lock_guard<mutex> guard_operation(lock_operation);
    log = fopen(filename.c_str(), "r");
    if (log == nullptr) {
      //create binary file to write
      log = fopn(filename.c_str(),"wb");
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
    bool onAuthDif = false;
    bool onKvUpt = false;
    bool onKvDel = false;
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
      if(strcmp(Tag.c_str(),AUTHENTRY.c_str()) == 0){
        onAuth = true;
      }
      else if(strcmp(Tag.c_str(), KVENTRY.c_str()) == 0){
        onKV = true;
      }
      else if(strcmp(Tag.c_str(),KVUPDATE.c_str()) == 0){
        onKvUpt = true;
      }
      else if(strcmp(Tag.c_str(), KVDELETE.c_str()) == 0){
        onKvDel = true;
      }
      else{
        onAuthDif = true;
      }
      counter += 8;
      //Case for authtable
      if(onAuth || onAuthDif){
        AuthTableEntry entry;
        string user;
        vector<uint8_t> salt;
        vector<uint8_t> pass_hass;
        vector<uint8_t> content;
        //read the length of username
        size_t user_size;
        memcpy(&user_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read username
        vector<uint8_t> user_block;
        for(int i = counter; i < counter + user_size; i++){
          user_block.push_back(*(d+i));
        }
        user.assign(user_block.begin(), user_block.end());
        entry.username = user;
        counter += user_size;

        //read length of salt
        size_t salt_size;
        memcpy(&salt_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read salt
        for(int i = counter; i < counter + salt_size; i++){
          salt.push_back(*(d+i));
        }
        entry.salt = salt;
        counter += salt_size;

        //read length of password
        size_t pass_size;
        memcpy(&pass_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read password
        for(int i = counter; i < counter +pass_size; i++){
          pass_hass.push_back(*(d+i));
        }
        entry.pass_hash = pass_hass;
        counter += pass_size;

        //read length of content
        size_t content_size;
        memcpy(&content_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read content if size > 0
        if(content_size > 0){
          for(int i = counter; i < counter + content_size; i++){
            content.push_back(*(d+i));
          }
          counter += content_size;
          entry.content = content;
        }
        else{
          entry.content = {};
        }
        //After reading, call insert()
        auth_table->insert(entry.username,entry,[](){} );
        while(counter % 8 != 0){
          counter += 1;
        }
      }
      else if(onAuthDif){
        string user;
        vector<uint8_t> content;
        //read the length of username
        size_t user_size;
        memcpy(&user_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read username
        vector<uint8_t> user_block;
        for(int i = counter; i < counter + user_size; i++){
          user_block.push_back(*(d+i));
        }
        user.assign(user_block.begin(), user_block.end());
        counter += user_size;
        //read length of content
        size_t content_size;
        memcpy(&content_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //read content if size > 0
        if(content_size > 0){
          for(int i = counter; i < counter + content_size; i++){
            content.push_back(*(d+i));
          }
          counter += content_size;
        }
        else{
          content = {};
        }
        //Define function to update content
        std::function<void(AuthTableEntry &)> f = [&](AuthTableEntry entry){
          entry.content = content;
          auth_table->upsert(user, entry, [](){}, [](){});
        };
        auth_table->do_with(user, f);
        while(counter % 8 != 0){
          counter += 1;
        }


      }
      else if(onKV || onKvUpt || onKvDel){
        string key;
        vector<uint8_t> val;
        //read the length of username
        size_t key_size;
        memcpy(&key_size, &load.at(counter), sizeof(size_t));
        counter += 8;
        //Read key
        vector<uint8_t> temp_key;
        for(int i = counter; i <counter + key_size; i++){
          temp_key.push_back(*(d+i));
        }
        key.assign(temp_key.begin(), temp_key.end());
        counter += key_size;
        //If KVDELETE, we delete the kv pair
        if(onKvDel){
          kv_store->remove(key, [](){});
        }
        else{
          //Read the length of value
          size_t val_size;
          memcpy(&val_size, &load.at(counter), sizeof(size_t));
          counter += 8;
          //Read val
          for(int i = counter; i < counter+val_size; i++){
            val.push_back(*(d+i));
          }
          counter += val_size;
          kv_store->insert(key, val, [](){});
          //If KVUPDATE
          if(onKvUpt){
            kv_store->upsert(key, val, [](){}, [](){});
          }
        }
        while(counter % 8 != 0){
          counter += 1;
        }
      }

    }
    //Change file mode to ab mode
    fclose(log);
    log = fopen(filename.c_str(), "ab");
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