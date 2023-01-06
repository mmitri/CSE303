/**
 * threads.cc
 *
 * Threads.cc demonstrates some of the ways that we can make threads and have
 * them interact.  This includes:
 * - Working on the same data (a counter)
 * - Working on different data (multiple counters)
 * - Producer/consumer interaction via a queue
 *
 * NB: we show both lock-based and nonblocking (via atomic) interactions
 */

#include <atomic>
#include <chrono>
#include <ctime>
#include <functional>
#include <libgen.h>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unistd.h>

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Use threads to collaborate on a task.\n", basename(progname));
  printf("  -n [int]    Number of work units per thread\n");
  printf("  -t [int]    Number of threads to run\n");
  printf("  -b [string] Behavior of the program\n");
  printf("              (options: counter, counters, queue\n");
  printf("  -h          Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The number of random ints to assign to each thread for "processing" */
  int num_ints = 64;

  /** The number of threads to use in the program */
  int num_threads = 1;

  /** name of the behavior to demonstrate */
  std::string behavior = "counter";

  /** Display a usage message? */
  bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 *
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "n:t:b:h")) != -1) {
    switch (opt) {
    case 'n':
      args.num_ints = atoi(optarg);
      break;
    case 't':
      args.num_threads = atoi(optarg);
      break;
    case 'b':
      args.behavior = std::string(optarg);
      break;
    case 'h':
      args.usage = true;
      break;
    }
  }
}

int main(int argc, char **argv) {
  arg_t args;
  parse_args(argc, argv, args);

  // if help was requested, give help, then quit
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // Run the appropriate workload
  if (args.behavior == "counter")
    run_counter_test(args);
  else if (args.behavior == "counters")
    run_counters_test(args);
  else if (args.behavior == "queue")
    run_queue_test(args);
  else
    printf("invalid behavior parameter %s\n", args.behavior.c_str());
}

void run_counter_test(arg_t &args) {
    // The lock and counter will end up on the same cache line, but that's
  // actually a good thing.
  std::mutex lock;
  uint64_t counter = 0;
  // note that the workload lambda captures the above variables, so they will be
  // shared by all threads who run the workload
  auto workload = [&](int) {
    for (int i = 0; i < args.num_ints; ++i) {
      // Be sure you understand how RAII (stack allocation of objects with
      // constructors and destructors) works.  This next line acquires the lock,
      // and the '}' releases it.
      std::lock_guard<std::mutex> sync(lock);
      counter++;
    }
  };
  // The above code just declared the experiment.  This runs it:
  run_timed_test(args, workload);
}

void run_counters_test(arg_t &args) {
     // declare a padded counter, which will have a size of 128 bytes
  //
  // NB: we need 128 bytes, because even though the L1 has 64-byte lines, the L2
  //     has adjacent-sector prefetch
  struct padded_counter {
    std::atomic<uint64_t> counter;
    char padding[128 - sizeof(std::atomic<uint64_t>)];
  };

  // An array of counters
  padded_counter counters[1024];
  for (int i = 0; i < 1024; ++i)
    counters[i].counter = 0;

  // note that the workload lambda captures the above variables, so they will be
  // shared by all threads who run the workload
  auto workload = [&](int id) {
    unsigned seed = (unsigned)id;
    for (int i = 0; i < args.num_ints; ++i) {
      // NB: Read the man page for thread-safe random number generation!
      int idx = rand_r(&seed) % 1024;
      counters[idx].counter++;
    }
  };
  run_timed_test(args, workload);
}

void run_queue_test(arg_t &args) {
    // A queue, and the lock that protects it
  std::mutex lock;
  std::queue<int> my_queue;

  // If the consumer threads get ahead of the producer, they may see an empty
  // queue, without emptiness indicating that the experiment is over.  An atomic
  // flag lets us know when we are really done.
  std::atomic<bool> done(false);

  // A few counters, for making sure the results are sane
  std::atomic<int64_t> sum(0);
  std::atomic<int> count(0);

  // note that the workload lambda captures the above variables, so they will be
  // shared by all threads who run the workload
  auto workload = [&](int id) {
    if (id == 0) {
      // thread 0 is the producer thread.  It will make num_ints work for each
      // consumer
      for (int i = 0; i < (args.num_threads - 1) * args.num_ints; ++i) {
        std::lock_guard<std::mutex> sync(lock);
        my_queue.push(i);
      }
      // production is done :)
      done = true;
    }
    // other threads are consumers.  They track how many times they succeed in
    // popping from the queue
    else {
      int64_t my_sum = 0;
      int my_count = 0;
      while (true) {
        std::lock_guard<std::mutex> sync(lock);
        if (my_queue.empty() && done)
          break; // NB: implicitly releases lock
        else if (!my_queue.empty()) {
          my_sum += my_queue.front();
          ++my_count;
          my_queue.pop();
        }
        // if the queue is empty but we're not done, release the lock and loop
        // around, so that hopefully the consumer can have a chance to do some
        // creating.
      }
      // The consumer thread is done: print its work, and update global sums
      printf("Thread/Count/Sum = (%d, %d, %ld)\n", id, my_count, my_sum);
      // NB: atomic<int> has thread-safe operator+=
      sum += my_sum;
      count += my_count;
    }
    // Everyone waits until all the work is done
    while (count != (args.num_threads - 1) * args.num_ints) {
    }
    // Producer outputs data that helps us to be sure things were correct
    if (id == 0)
      printf("Total Sum: %ld\n", sum.load());
  };
  run_timed_test(args, workload);
}

/**
 * The counter test instructs a plurality of threads to increment the same
 * counter.  We should expect this test to fail to exhibit scaling, because all
 * of the threads are trying to work on the same counter at the same time.
 *
 * Note, too, that in this case we are protecting the counter with a lock
 *
 * @param args The bundle of arguments to the program
 */
void run_counter_test(arg_t &args) {
  // The lock and counter will end up on the same cache line, but that's
  // actually a good thing.
  std::mutex lock;
  uint64_t counter = 0;
  // note that the workload lambda captures the above variables, so they will be
  // shared by all threads who run the workload
  auto workload = [&](int) {
    for (int i = 0; i < args.num_ints; ++i) {
      // Be sure you understand how RAII (stack allocation of objects with
      // constructors and destructors) works.  This next line acquires the lock,
      // and the '}' releases it.
      std::lock_guard<std::mutex> sync(lock);
      counter++;
    }
  };
  // The above code just declared the experiment.  This runs it:
  run_timed_test(args, workload);
}

/**
 * Launch a bunch of threads that all execute the same task, and time how
 * long it takes to launch threads, run code, and wait for all threads to end.
 * 
 * @param args The arguments to the program
 * @param task The task that each thread should run
 */
void run_timed_test(arg_t &args, std::function<void(int)> task){
    using namespace std::chrono;

    // Note: we will include the time to create and destroy threads as part of the measured time.
    // As long as the time to do the work is big enough, that's OK.
    high_resolution_clock::time_point t1 = high_resolution_clock::now();

    // Launch all the threads
    std::thread threads[args.num_threads];
    for(int i=0;i<args.num_threads;++i){
        threads[i] = std::thread(task,i);
    }
    // Wait for all threads to finish
    for(auto &th : threads){
        th.join();
    }

    // report total time
    high_resolution_clock::time_point t2 = high_resolution_clock::now();
    duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
    printf("Total time: %lf seconds\n", time_span.count());
}