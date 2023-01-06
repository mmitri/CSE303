# Assignment #2: A Concurrent Key/Value Store

The purpose of this assignment is to practice using concurrency in a realistic
setting.

## Do This First

Immediately after pulling `p2` from Bitbucket, you should start a container,
navigate to the `p2` folder, and type `chmod +x solutions/*.exe`.  This command
only needs to be run once.  It will make sure that certain files from the
assignment have their executable bit set.

## Assignment Details

There are two main reasons for using concurrency.  One of them, which is more
typically called "parallelism", is the desire to use multiple CPU cores to get a
job done in less time.  The second involves overlapping communication with
computation.  Often, these go hand in hand. As an example, consider our server
from assignment 1.  For the entire time that the server is responding to one
client, it cannot even accept a connection from another client.  Certainly it
would be good if we could overlap one client's operations in the directory with
another client's network communication.  But what if two clients need to access
the `directory` at the same time?  We can make the `directory` thread-safe by
protecting it with a `mutex`, but that's not going to let us use many cores to
satisfy many requests at the same time.

In this assignment, we are going to extend our client and server in two main
ways.  The first is that we are going to add a new feature to the server, a
"key/value" store (KVS).  This new data structure will be a hash table into
which clients can store arbitrary data (the value) by giving it a unique name
(the key, a `std::string`).  The client will need to be able to perform five new
operations:

* KVI: Key/Value `Insert`: insert a new key/value pair into the server's KVS
* KVD: Key/Value `Delete`: remove an existing key/value pair from the server's KVS
* KVG: Key/Value `Get`: get the value associated with a key
* KVU: Key/Value `Upsert`: set or change the value for a key in the server's KVS
* KVA: Key/Value `All`: get a list of all the keys in the server's KVS

These changes to the client are relatively straightforward, and we have done
them for you.  You do not need to edit the client code at all.  In fact, we
don't even compile the client anymore.  Your focus should be entirely on the
server.

First and foremost, we will need a way for the server to give incoming requests
to concurrent threads.  Our solution will be to create a new "thread pool".  The
thread pool can be thought of as a single-producer multi-consumer queue.  Each
time a new connection arrives, the server's main thread should accept the
connection and put it into the queue.  Worker threads will be blocked trying to
pop elements from the queue.  The worker threads can then read the requests,
compute results, and send them back to clients.

The other main task will be to make the server's data structures thread-safe. We
could do this by protecting each with a coarse-grained `std::mutex` object.
However, that's not going to be particularly good for performance.  Instead, we
will create a concurrent, generic hash table.  When the hash table is complete,
we will be able to use it twice: for the KVS, and for the authentication table.
Note that it will be important to think very carefully about two-phase locking
for this new hash table... the comments in the provided code are a good place to
start.

Finally, it will be necessary to update the persistence mechanism of our server,
because the new functionalities will need to be incorporated into the way that
we persist data.  Again, see the comments in the provided code for details of
the new persistence requirements.  You should be sure to think about two-phase
locking.

## Getting Started

Your git repository has a new folder, `p2`, which contains a significant portion
of the code for the final solution to this assignment.  It also includes binary
files that represent much of the solution to assignment 1.  The `Makefile` has
been updated so that you do not need to have completed the first assignment in
order to get full credit for this assignment.

There is a test script called `scripts/p2.py`, which you can use to test your
code.  Note that these tests are not sufficient to show that your code is
thread-safe and free of data races.  We will inspect your code to evaluate its
correctness in the face of concurrency, and also test it to see if it scales.

## Tips and Reminders

While a real server cannot be concurrent until it has a thread pool, in this
assignment you can start with any of the three files.  The `just_my` makefiles
will allow you to test each independently.

As in the last assignment, you should keep in mind that subsequent assignments
will build upon this... so as you craft a solution, be sure to think about how
to make it maintainable.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

As always, please be careful about not committing unnecessary files into your
repository.

Your server should **not** store plain-text passwords in the file.

## Grading

The `scripts` folder has four python scripts that exercise the main portions of
the assignment: basic authentication and correctness, file-based persistence,
the thread pool, and the hash table.  These scripts use specialized `Makefiles`
that integrate some of the solution code with some of your code, so that you can
get partial credit when certain portions of your code work.  Note that these
`Makefiles` are very strict: they will crash on any compiler warning.  You
should *not* turn off these warnings; they are there to help you.  If your code
does not compile with these scripts, you will not receive any credit.  If you
have partial solutions and you do not know how to coerce the code into being
warning-free, you should ask the professor.

If the scripts pass when using your client with our server, and when using our
client with your server, then you will receive full "functionality" points for
that portion of the assignment.  We will manually inspect your code to determine
if it is correct with regard to concurrency.  As before, we reserve the right to
deduct "style" points if your code is especially convoluted.  Please be sure to
use your tools well.  For example, Visual Studio Code (and emacs, and vim) have
features that auto-format your code.  You should use these features.

While it is our intention to give partial credit, *no credit will be given for
code that does not compile without warnings.*  If you decide to move functions
between files, or add files, or do other things that break the scripts in the
grading folder, then you will lose at least 10%. If you think some change is
absolutely necessary, speak with the professor first.

There are five main graded portions of the assignment:

* Is the thread pool correct?
  * Files: `common/my_pool.cc`
* Does the server's handle client requests correctly?
  * Files: `server/my_storage.cc`
* Is the concurrent hash table Store implemented correctly?
  * Files: `common/concurrenthashmap.h`
* Is persistence implemented correctly, and according to `format.h`
  * Files: `server/my_storage.cc`
* Does the Key/Value store scale?
  * Files: `common/concurrenthashmap.h`

Note: for the fifth part of the assignment, we have provided a separate `bench`
folder, which has a benchmark you can use to test scalability.  Be sure to pay
careful attention to your Docker settings.  By default, Docker does not give
many cores to each container, so you may find that you aren't seeing
scalability, even though your laptop has many cores.

Also, note that we have removed a lot of code from the `p2` folder, and instead
are providing `.o` files for the corresponding libraries.  This means, for
example, that if you did not correctly implement cryptography in the last
assignment, it will not affect your grade in this assignment.  In fact, we are
providing a complete `client.exe`, and expecting all of your work to only be in
three files: `common/my_pool.cc`, `server/concurrenthashmap.h`, and
`server/my_storage.cc`.  You will probably want to begin by re-using a lot of
your `server/my_storage.cc` code from the last assignment.

Remember that the graded components are intentionally vague: you need to start
thinking about what it means for code to be "correct".  There are many criteria
that cannot be established through unit testing.  This is especially true when
thinking about race freedom and serializability.

## Notes About the Reference Solution

In the following subsections, you will find some details about the reference
solution.

### `server/my_storage.cc`

The reference solution is about 500 lines, including comments.  Most of the
functions are not implemented at all.  Note that the fields of `Storage` are
complete.  They provide everything that you need to implement storage correctly.

One of the biggest challenges in this code is to get the concurrency correct,
and it's hard to do because our tests won't crash if the concurrency is wrong.
In particular, while it is fine to assume that `load()` will only be called
once, before there are threads, and thus does not need concurrency, you cannot
assume the same about any other methods.  You will need to use two-phase locking
to `persist()` correctly.  The easiest way is to chain lambdas together.  If you
aren't sure how, you should think carefully about the `do_all_readonly()` method
of the hash table.

Most of the K/V operations are relatively straightforward once you've got
everything else working.  For example, the code for `kv_upsert()` looks
something like this:

```c++
  auto r = auth(user, pass);
  if (!r.succeeded)
    return {false, r.msg, {}};
  if (fields->kv_store.upsert(key, vector(val))) 
    return {true, RES_OKINS, {}};
  return {true, RES_OKUPD, {}};
```

### `common/my_pool.cc`

The thread pool is fundamental to having any concurrency in your server.  
Consider the old implementation of `accept_client()` from p0:

```c++
/// Given a listening socket, start calling accept() on it to get new
/// connections.  Each time a connection comes in, use the provided handler to
/// process the request.  Note that this is not multithreaded.  Only one client
/// will be served at a time.
///
/// @param sd The socket file descriptor on which to call accept
/// @param handler A function to call when a new connection comes in
void accept_client(int sd, function<bool(int)> handler) {
  // Use accept() to wait for a client to connect.  When it connects, service
  // it.  When it disconnects, then and only then will we accept a new client.
  while (true) {
    cout << "Waiting for a client to connect...\n";
    sockaddr_in clientAddr = {0};
    socklen_t clientAddrSize = sizeof(clientAddr);
    int connSd = accept(sd, (sockaddr *)&clientAddr, &clientAddrSize);
    if (connSd < 0) {
      close(sd);
      sys_error(errno, "Error accepting request from client: ");
      return;
    }
    char clientname[1024];
    cout << "Connected to "
         << inet_ntop(AF_INET, &clientAddr.sin_addr, clientname,
                      sizeof(clientname))
         << endl;
    bool done = handler(connSd);
    // NB: ignore errors in close()
    close(connSd);
    if (done)
      return;
  }
}
```

Each time a new socket connection happened, the server would directly execute
the handler to parse the request, decrypt it, and interact with
`server_storage.h` accordingly.  If an operation in `server_storage.h` took a
long time, then no other requests would be satisfied in the meantime.

The purpose of a thread pool is to overcome this sequential bottleneck.  The
thread pool is essentially a bunch of threads that are all waiting (by using a
condition variable) for things to arrive in a queue.  When the main thread (the
one who is running `accept_client`) receives a new connection, it should just
push it into the queue and then wait for the next connection to arrive.

Let's look at the new `accept_client()` code:

```c++
/// Given a listening socket, start calling accept() on it to get new
/// connections.  Each time a connection comes in, pass it to the thread pool so
/// that it can be processed.
///
/// @param sd   The socket file descriptor on which to call accept
/// @param pool The thread pool that handles new requests
void accept_client(int sd, thread_pool &pool) {
  atomic<bool> safe_shutdown(false);
  pool.set_shutdown_handler([&]() {
    safe_shutdown = true;
    shutdown(sd, SHUT_RDWR);
  });
  // Use accept() to wait for a client to connect.  When it connects, 
  // hand it to a thread pool for servicing.
  while (pool.check_active()) {
    cout << "Waiting for a client to connect...\n";
    sockaddr_in clientAddr = {0};
    socklen_t clientAddrSize = sizeof(clientAddr);
    int connSd = accept(sd, (sockaddr *)&clientAddr, &clientAddrSize);
    if (connSd < 0) {
      // If safe_shutdown() was called, and it's EINVAL, then the pool has been
      // halted, and the listening socket closed, so don't print an error.
      if (errno != EINVAL || !safe_shutdown)
        sys_error(errno, "Error accepting request from client: ");
      return;
    }
    char clientname[1024];
    cout << "Connected to "
         << inet_ntop(AF_INET, &clientAddr.sin_addr, clientname,
                      sizeof(clientname))
         << endl;
    pool.service_connection(connSd);
  }
}
```

This code is mostly the same, except that it just hands the connection to a
pool, instead of handling it.  However, there is one other important difference:
what happens on a `BYE` message.  Before, the main thread was processing each
message, so it would receive a `BYE`, `handler()` would return false, and it
would exit the loop.  Now we need some way for the threads of the pool to
communicate back to the main thread.  We do this by sending a `shutdown_handler`
lambda to the pool.  This handler tells the pool how to notify the main thread
of a `BYE` message.

The code above is trickier than it seems: the code in the handler is not run by
the main thread, but by *one of* the threads in the pool.  To prevent races, we
need to use an `atomic` variable.  Since the main thread may be blocked in a
call to `accept`, we also need to `shutdown` the socket.  While we provide this
code for you, it highlights an important point: thinking about concurrency is
much more difficult than thinking about sequential code.

With all of the above as background, note that `pool.cc` is only about 130 lines
of code.  You will need to use a `queue`, a `mutex`, and a `condition variable`
in your `Internal` class.  You will also need to have an `atomic` variable for
letting a thread who receives `BYE` indicate to other threads that they should
not keep waiting on the queue (probably in addition to broadcasting on the
condition variable).

### `server/concurrenthashmap.h`

The hash table you create needs to be concurrent, and it needs to be scalable,
but it does not need to be particularly clever.  It is sufficient to have a
fixed-size array/vector (whose size is governed by a command-line argument) of
`std::list`s.  Then you can have a single mutex per entry in the
fixed-size array, and you'll end up with a reasonably scalable hash table.

You will need to implement your hash table correctly, so that it can be
instantiated twice in `server/my_storage.cc` file: once for the directory, and
once for the key/value store.

There are some basic concurrency best practices you should follow, like using
mutexes *even when reading* and using `lock_guard`.  The hardest part though is
remembering to use two-phase locking (2PL) everywhere where more than one bucket
is accessed.  Recall that with 2PL, all locks that an operation might acquire
*must* be acquired before any lock is released.  This can be done by
incrementally growing the lock set, and releasing all at the end; by
aggressively locking everything early, and then releasing as the data structure
is released; or by aggressively locking everything early, and then releasing
everything at the end.  We won't be testing the performance of your 2PL code, so
you don't really need to worry about which one performs best.  However, you will
need to implement `do_all_readonly` carefully, since it will be used by your
`my_storage.cc` file in the `persist()` method.

The good news is that the reference solution is only about 150 lines of code.
But as you probably have guessed by now, there is a lot of subtlety to getting
that code to be correct.

## Collaboration and Getting Help

You may work in teams of 2 for this assignment.  If you plan to work in a team,
you must notify the instructor by September 24th, so that we can set up your
repository access (be sure to cc your teammate, and to inform us of which
repository you want shared).  If you notify us after that date, we will deduct
10 points. If you wish to have a different team than in the last assignment, or
to disband your team and work alone, please contact the professor by September
24th. If you are working in a team, you should **pair program** for the entire
assignment. After all, your goal is to learn together, not to each learn half
the material.

If you require help, you may seek it from any of the following sources:

* The professor and TAs, via office hours or Piazza
* The Internet, as long as you use the Internet as a read-only resource and do
  not post requests for help to online sites.

It is not appropriate to share code with past or current CSE 303 / CSE 403
students, unless you are sharing code with your teammate.

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.

## Deadline

You should be done with this assignment before 11:59 PM on October 15th, 2022.
Please be sure to `git commit` and `git push` before that time, so that we can
promptly collect and grade your work.
