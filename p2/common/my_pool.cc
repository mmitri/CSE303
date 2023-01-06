#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

/// The general structure I found for this is from
/// https://stackoverflow.com/questions/15752659/thread-pooling-in-c11
class my_pool : public thread_pool {
public:
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) {
    job = handler;
    // Initialize all of the threads with the loop function
    for(int i = 0; i < size; i++){
      threads.push_back(thread(&my_pool::loop, this));
    }
  }

  void loop();

  /// destruct a thread pool
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    shutdown_handler = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    return !terminate;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    cv.notify_all(); // notify all worker threads
    for(size_t i = 0; i < threads.size(); i++){
      threads[i].join(); // wait for each thread to finish
    }
    threads.clear(); // clear the vector of threads
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    // unique lock will automatically release when out of scope
    {
      unique_lock<mutex> lock(mutex_lock); // acquire scoped lock
      jobs.push(sd); // Add the sd to the queue
    } // release the lock
    cv.notify_one(); // notify a worker thread
  }
private: 
  vector<thread> threads;
  mutex mutex_lock;
  condition_variable cv;
  queue<int> jobs;
  atomic_bool terminate = false;
  function<void()> shutdown_handler;
  function<bool(int)> job;
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  return new my_pool(size, handler);
}

/// Infinite loop for the worker threads
/// They aquire a lock, then use a condition variable to wait
/// for a connection, then they service the request
void my_pool::loop(){
  while (true){
      int sd;
      {
        unique_lock<mutex> lock(mutex_lock); // Get scoped lock
        cv.wait(lock, [this] { // Wait for a signal
          return !jobs.empty() || terminate; // Once it gets a signal, it will only continue if this is true
        });
        if (terminate){ // If we got a signal and terminate is true, just return
          return;
        }
        sd = jobs.front(); // set sd to the front item in the queue
        jobs.pop(); // pop the front off the queue
      } // lock gets released
      if (job(sd)){ // if parse_requests returns true, means shutdown
        shutdown_handler(); // call shutdown handler
        {
          unique_lock<mutex> lock(mutex_lock); // acquire lock (not sure if needed or not because terminate is atomic)
          terminate = true; // set terminate to true
        }
        return; // If we're going to terminate then just return
      }
      close(sd); // close the socket descriptor to end that client request
    }
}
