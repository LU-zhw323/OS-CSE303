#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

class my_pool : public thread_pool {
private:
  //queue where we store request(where worker thread should read from)
  queue<int> sd_pool;
  //lock of the pool
  mutex Lock;
  //Condition_variable
  condition_variable cond;
  //vector of worker threads
  vector<thread> workers;
  //atomic boolean of shut_down hander
  atomic<bool> active = true;
  //shutdown_handler
  function<void()> shutdown_handler;
  
public:
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) {
    //Construct worker threads
    for(int i = 0; i < size; i++){
      //Lambda function that wokrers should work on
      auto work = [&](){
        while(active){
          //lock before wait()
          unique_lock<mutex> lock(Lock);
          //Block current thread if the queue is empty
          while(sd_pool.empty()){
            cond.wait(lock);
          }
          //Proceed to take sd from the queue
          int current_sd = sd_pool.front();
          sd_pool.pop();
          //handle request
          bool result = handler(current_sd);
          //Where we receive 'BYE'
          if(result){
            active = false; //signal that pool needs to be shut down
            cond.notify_all(); //woke up all blocked thread
            shutdown_handler(); //call shutdown_handler()
          }
          close(current_sd);
        }
      };
      workers.push_back(thread(work));
    }
  }

  /// destruct a thread pool
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    //set shutdown_handler received from accpet_client()
    shutdown_handler = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    return active;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    cout << "my_pool::await_shutdown() is not implemented";
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    //Always Lock before we change condition variable
    unique_lock<mutex> lock(Lock);
    //Insert socket descriptor to the queue
    sd_pool.push(sd);
    //woke up one thread to work on this request
    cond.notify_one();
  }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  //return new thread_pool object
  return new my_pool(size, handler);
}
