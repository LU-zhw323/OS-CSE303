#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"
using namespace std;
using std::begin, std::end;

/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {

//Create bucket struct
struct bucket{
  list<pair<K,V>> pairs;    //List of key/value pairs
  mutex Lock;               //Lock per bucket
};
//Vector of buckets
vector<bucket*> kvstore;




public:



  ///Helper function to find the position of key in the kvstore by std::hash
  ///@param key The key that we need to find its position in the hash table
  ///
  ///@return The poistion of the key value in the table
  int prehash(K key){
    hash<K> hash_key;
    size_t hash_val = hash_key(key);
    int preHash = (int)hash_val % kvstore.size();
    return preHash;
  }


  /// Construct by specifying the number of buckets it should have
  ///
  /// @param _buckets The number of buckets
  ConcurrentHashMap(size_t _buckets) {
    //Push back buckets to entries til size = _buckets
    while(kvstore.size() < _buckets){
      kvstore.push_back(new bucket());
    }
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() {
    kvstore.clear();
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    for(int i = 0; i < kvstore.size(); i++){
      //Perform 2PL to lock all buckets
      const lock_guard<mutex> guard(kvstore[i]->Lock);
      kvstore[i]->pairs.clear();
    }

  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    //Prehash to find the position of the key
    int position = prehash(key);
    //Acquire lock on specific bucket
    const lock_guard<mutex> guard(kvstore[position]->Lock);
    //Find if key exists
    size_t size_pairs = kvstore[position]->pairs.size();
    auto target_bucket = kvstore[position];
    auto iter = kvstore[position]->pairs.begin();
    while(iter != kvstore[position]->pairs.end()){
      if((*iter).first == key){
        return false; //lock_guard unlock
      }
      iter ++;
    }
    //Insert new key/value pair
    target_bucket->pairs.push_back(make_pair(key, val));
    on_success();
    return true; //lock_guard will unlock
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    //Prehash to find the position of the key
    int position = prehash(key);
    //Acquire lock on specific bucket
    const lock_guard<mutex> guard(kvstore[position]->Lock);
    //Find if key exists, and set val
    size_t size_pairs = kvstore[position]->pairs.size();
    auto target_bucket = kvstore[position];
    auto iter = kvstore[position]->pairs.begin();
    while(iter != kvstore[position]->pairs.end()){
      if((*iter).first == key){
        (*iter).second = val;
        on_upd();
        return false; //lock guard unlock
      }
      iter ++;
    }

    //Insert new key/value pair
    target_bucket->pairs.push_back(make_pair(key, val));
    on_ins();
    return true; //lock_guard will unlock

  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    //Prehash to find the position of the key
    int position = prehash(key);
    //Acquire lock on specific bucket
    const lock_guard<mutex> guard(kvstore[position]->Lock);
    //Find if key exists, and set val
    size_t size_pairs = kvstore[position]->pairs.size();
    auto target_bucket = kvstore[position];
    auto iter = kvstore[position]->pairs.begin();
    while(iter != kvstore[position]->pairs.end()){
      if((*iter).first == key){
        f((*iter).second);
        return true; //lock_guard unlock
      }
      iter ++;
    }
    return false; //lock_guard unlock
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    //Prehash to find the position of the key
    int position = prehash(key);
    //Acquire lock on specific bucket
    const lock_guard<mutex> guard(kvstore[position]->Lock);
    //Find if key exists, and set val
    size_t size_pairs = kvstore[position]->pairs.size();
    auto target_bucket = kvstore[position];
    auto iter = kvstore[position]->pairs.begin();
    while(iter != kvstore[position]->pairs.end()){
      if((*iter).first == key){
        f((*iter).second);
        return true; //lock_guard unlock
      }
      iter ++;
    }
    return false; //lock_guard unlock
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
     //Prehash to find the position of the key
    int position = prehash(key);
    //Acquire lock on specific bucket
    const lock_guard<mutex> guard(kvstore[position]->Lock);
    //Find if key exists, and set val
    size_t size_pairs = kvstore[position]->pairs.size();
    auto target_bucket = kvstore[position];
    auto iter = kvstore[position]->pairs.begin();
    while(iter != kvstore[position]->pairs.end()){
      if((*iter).first == key){
        target_bucket->pairs.erase(iter);
        on_success();
        return true; //lock_guard unlock
      }
      iter ++;
    }
    return false; //lock_guard unlock
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
    auto bucket_iter = kvstore.begin();
    while(bucket_iter != kvstore.end()){
      bucket* current_buck = (*bucket_iter);
      current_buck->Lock.lock();
      auto pair_iter = current_buck->pairs.begin();
      while(pair_iter != current_buck->pairs.end()){
        f((*pair_iter).first,(*pair_iter).second);
        pair_iter ++;
      }
      if(bucket_iter+1 == kvstore.end()){
        then();
      }
      bucket_iter ++;
      current_buck->Lock.unlock();
    }
  }
};
