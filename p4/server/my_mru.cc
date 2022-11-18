#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {
  //size of the data structure(max size)
  size_t deque_size;
  //data structure
  deque<string> mru;
  //mutex lock
  mutex mru_lock;

public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) {deque_size = elements;}

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
    //Lock before operation
    lock_guard<mutex> guard(mru_lock);
    //Check the size of data structure
    if(mru.size() > deque_size){
      mru.pop_back();
    }
    //remove duplicates
    auto p = mru.begin();
    while(p != mru.end()){
      if(*p == elt){
        mru.erase(p);
        break;
      }
      p += 1;
    }
    //insert as mru
    mru.push_front(elt);
  }

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {
    //Lock before operation
    lock_guard<mutex> guard(mru_lock);
    //remove target
    auto p = mru.begin();
    while(p != mru.end()){
      if(*p == elt){
        mru.erase(p);
        break;
      }
      p += 1;
    }
  }

  /// Clear the mru_manager
  virtual void clear() { 
    //Lock before operation
    lock_guard<mutex> guard(mru_lock);
    mru.clear();
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() {
    string res = "";
    if(mru.size() > 0){
      auto p = mru.begin();
      while(p != mru.end()){
        res += *p + "\n";
        p += 1;
      }
    }
    return res;
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }