#include <atomic>
#include <iostream>
#include <libgen.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "../server/concurrenthashmap.h"

using namespace std;

/// Create an instance of Map that can be used for integer set benchmarks
///
/// @param _buckets The number of buckets in the table
Map<int, int> *intset_factory(size_t _buckets) {
  return new ConcurrentHashMap<int, int>(_buckets);
}

/// arg_t represents the command-line arguments to the benchmark
struct arg_t {
  size_t keys = 1024;     // Key range (e.g., 65536 for a range of 1..65535)
  size_t threads = 1;     // Number of threads
  size_t reads = 80;      // Lookup percent.  Half the remainder will be inserts
  size_t iters = 1048576; // Iterations per thread
  size_t buckets = 1024;  // Number of buckets for the server's hash tables

  /// Construct an arg_t from the command-line arguments to the program
  ///
  /// @param argc The number of command-line arguments passed to the program
  /// @param argv The list of command-line arguments
  ///
  /// @throw An integer exception (1) if an invalid argument is given, or if
  ///        `-h` is passed in
  arg_t(int argc, char **argv) {
    // NB: We don't do any validation of the arguments
    long opt;
    while ((opt = getopt(argc, argv, "k:t:r:i:b:h")) != -1) {
      switch (opt) {
      case 'k':
        keys = atoi(optarg);
        break;
      case 't':
        threads = atoi(optarg);
        break;
      case 'r':
        reads = atoi(optarg);
        break;
      case 'i':
        iters = atoi(optarg);
        break;
      case 'b':
        buckets = atoi(optarg);
        break;
      default: // on any error, print a help message.  This case subsumes `-h`
        throw 1;
        return;
      }
    }
  }

  /// Display a help message to explain how the command-line parameters for this
  /// program work
  ///
  /// @progname The name of the program
  static void usage(char *progname) {
    cout << basename(progname) << ": Hash Table (Integer Set) Benchmark\n"
         << "  -k [int] Key range\n"
         << "  -t [int] Threads\n"
         << "  -r [int] Read-only percent\n"
         << "  -i [int] Iterations per thread\n"
         << "  -b [int] Number of buckets\n"
         << "  -h       Print help (this message)\n";
  }
};

/// An enum for the 6 events that can happen in an intset benchmark
enum EVENTS { INS_T, INS_F, RMV_T, RMV_F, LOK_T, LOK_F, COUNT };

int main(int argc, char **argv) {
  // Parse the command-line arguments
  //
  // NB: It would be better not to put the arg_t on the heap, but then we'd need
  //     an extra level of nesting for the body of the rest of this function.
  arg_t *args;
  try {
    args = new arg_t(argc, argv);
  } catch (int i) {
    arg_t::usage(argv[0]);
    return 1;
  }

  // Print configuration
  cout << "# (k,t,r,i,b) = (" << args->keys << "," << args->threads << ","
       << args->reads << "," << args->iters << "," << args->buckets << ")\n";

  // Make a hash table, populate it with 50% of the keys.  We ignore values
  auto tbl = intset_factory(args->buckets);
  for (size_t i = 0; i < args->keys; i += 2)
    tbl->insert(i, 0, []() {});

  // These variables are needed by the threads in order to measure time
  // correctly
  chrono::high_resolution_clock::time_point start_time, end_time;
  atomic<size_t> barrier_1(0), barrier_2(0), barrier_3(0);
  atomic<uint64_t> stats[EVENTS::COUNT];
  for (auto i = 0; i < EVENTS::COUNT; ++i)
    stats[i] = 0;

  // launch a bunch of threads, wait for them to finish
  vector<thread> threads;
  for (size_t i = 0; i < args->threads; ++i) {
    threads.push_back(thread(
        [&](int tid) {
          // init a thread-local stats counter
          uint64_t my_stats[EVENTS::COUNT] = {0};

          // Announce that this thread has started, wait for all to start
          ++barrier_1;
          while (barrier_1 != args->threads) {
          }

          // All threads are started.  Thread 0 reads the clock
          if (tid == 0)
            start_time = chrono::high_resolution_clock::now();
          ++barrier_2;
          while (barrier_2 != args->threads) {
          }

          // Everyone can start now
          unsigned seed = tid;
          for (size_t o = 0; o < args->iters; ++o) {
            size_t action = rand_r(&seed) % 100;
            size_t key = rand_r(&seed) % args->keys;
            if (action < args->reads) {
              if (tbl->do_with_readonly(key, [](int) {}))
                ++my_stats[EVENTS::LOK_T];
              else
                ++my_stats[EVENTS::LOK_F];
            } else if (action < args->reads + (100 - args->reads) / 2) {
              if (tbl->insert(key, 0, []() {}))
                ++my_stats[EVENTS::INS_T];
              else
                ++my_stats[EVENTS::INS_F];
            } else {
              if (tbl->remove(key, []() {}))
                ++my_stats[EVENTS::RMV_T];
              else
                ++my_stats[EVENTS::RMV_F];
            }
          }

          // Wait for everyone to finish before reading the clock in thread 0
          ++barrier_3;
          while (barrier_3 != args->threads) {
          }
          if (tid == 0)
            end_time = chrono::high_resolution_clock::now();

          // Add threads' counts to global counters
          for (auto i = 0; i < EVENTS::COUNT; ++i)
            stats[i] += my_stats[i];
        },
        i));
  }
  for (size_t i = 0; i < args->threads; ++i)
    threads[i].join();

  // Generate output using the elapsed time and the counts
  auto dur =
      chrono::duration_cast<chrono::duration<double>>(end_time - start_time)
          .count();
  uint64_t ops = 0;
  for (auto i = 0; i < EVENTS::COUNT; ++i)
    ops += stats[i];
  cout << "Throughput (ops/sec): " << ops / dur << endl;
  cout << "Execution Time (sec): " << dur << endl;
  cout << "Total Operations:     " << ops << endl;
  cout << "  Lookup (True) :     " << stats[EVENTS::LOK_T] << endl;
  cout << "  Lookup (False):     " << stats[EVENTS::LOK_F] << endl;
  cout << "  Insert (True) :     " << stats[EVENTS::INS_T] << endl;
  cout << "  Insert (False):     " << stats[EVENTS::INS_F] << endl;
  cout << "  Remove (True) :     " << stats[EVENTS::RMV_T] << endl;
  cout << "  Remove (False):     " << stats[EVENTS::RMV_F] << endl;

  delete args;
  return 0;
}
