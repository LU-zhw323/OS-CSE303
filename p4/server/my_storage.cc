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
#include<mutex>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "persist.h"
#include "quotas.h"
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

  /// The open file
  FILE *storage_file = nullptr;

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

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
  MyStorage(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
            size_t rqq, double qd, size_t top, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    // TODO: you probably want to free some memory here...
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return add_user_helper(user, pass, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return set_user_data_helper(user, pass, content, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_user_data_helper(user, pass, who, auth_table);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return auth_helper(user, pass, auth_table);
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
    // NB: log_sv() in persist.h (implementation in persist.o) will be helpful
    //     here
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
    //Lock operation
    const lock_guard<mutex> guard_operation(lock_operation);
    //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Add quota
    bool err_req = false;
    bool err_up = false;
    std::function<void(const vector<uint8_t> &)> f = [&](Quotas* quota){
      //add 1 threshold to req quota
      err_req = quota->requests->check_add(1);
      //add size of val to upload quota
      err_up = quota->uploads->check_add(val.size());
    };
    quota_table->do_with(user, f);
    if(!err_req){
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(!err_up){
      return {false, RES_ERR_QUOTA_UP, {}};
    }
    //insert key
    std::function<void()> on_success = [&](){
      log_sv(storage_file, KVENTRY, key, val);
    };
    bool res = kv_store->insert(key,val,on_success);
    if(!res){
      return{false, RES_ERR_KEY, {}};
    }
    //add to mru
    mru->insert(key);
    return{true, RES_OK, {}};
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
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Add quota
    bool err_req = false;
    std::function<void(const vector<uint8_t> &)> f = [&](Quotas* quota){
      //add 1 threshold to req quota
      err_req = quota->requests->check_add(1);
    };
    quota_table->do_with(user, f);
    if(!err_req){
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    //Get key/value from the kvstore
    vector<uint8_t> info;
    std::function<void(const vector<uint8_t> &)> f = [&](vector<uint8_t> val){
      info.insert(end(info), begin(val), end(val));
    };
    bool result = kv_store->do_with_readonly(key, f);
    if(!result){
      return{false, RES_ERR_KEY, {}};
    }
    //Check if we can add to download quota
    bool err_down = false;
    std::function<void(const vector<uint8_t> &)> F = [&](Quotas* quota){
      //add val.size() threshold to req quota
      err_down = quota->downloads->check_add(info.size());
    };
    quota_table->do_with(user, F);
    if(!err_down){
      return {false, RES_ERR_QUOTA_DOWN, {}};
    }
    mru->insert(key);
    return {true, RES_OK, info};

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
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    //Lock operation
    const lock_guard<mutex> guard_operation(lock_operation);
    //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    bool err_req = false;
    std::function<void(const vector<uint8_t> &)> f = [&](Quotas* quota){
      //add 1 threshold to req quota
      err_req = quota->requests->check_add(1);
    };
    quota_table->do_with(user, f);
    if(!err_req){
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    //remove and write log
    bool res = kv_store->remove(key, log_s(storage_file, KVDELETE, key));
    if(!res){
      return {false,RES_ERR_KEY, {}};
    }
    //remove from mru
    mru->remove(key);
    return {true, RES_OK,{}};
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // NB: log_sv() in persist.h (implementation in persist.o) will be helpful
    //     here
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
    //Lock operation
    const lock_guard<mutex> guard_operation(lock_operation);
     //Authorize user and pass
    auto Auth = auth(user, pass);
    if(!Auth.succeeded){
      return{false, RES_ERR_LOGIN, {}};
    }
    //Add quota
    bool err_req = false;
    bool err_up = false;
    std::function<void(const vector<uint8_t> &)> f = [&](Quotas* quota){
      //add 1 threshold to req quota
      err_req = quota->requests->check_add(1);
      //add size of val to upload quota
      err_up = quota->uploads->check_add(val.size());
    };
    quota_table->do_with(user, f);
    if(!err_req){
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(!err_up){
      return {false, RES_ERR_QUOTA_UP, {}};
    }
    bool res = kv_store->upsert(kay,val, log_sv(storage_file, KVENTRY, key, val), log_sv(storage_file,KVUPDATE, key.val));
    //update mru
    mru->insert(key);
    if(res){
      //Insert case
      return{true, RES_OKINS, {}};
    }
    else{
      return {true, RES_OKUPD, {}};
    }
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    cout << "my_storage.cc::kv_all() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    cout << "my_storage.cc::kv_top() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    // NB: Based on how the other methods are implemented in the helper file, we
    //     need this command here:
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // NB: the helper (.o provided) does all the work for this operation :)
    return save_file_helper(auth_table, kv_store, filename, storage_file);
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    // NB: the helper (.o provided) does all the work from p1/p2/p3 for this
    //     operation.  Depending on how you choose to implement quotas, you may
    //     need to edit this.
    return load_file_helper(auth_table, kv_store, filename, storage_file);
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
