# Assignment #4: Enforcing Quotas and Managing Resources

The purpose of this assignment is to implement some standard resource management
concepts: quotas and most-recently-used (MRU) tracking.  (Remember: MRU tracking
and LRU eviction are equivalent!)

## Do This First

Immediately after pulling `p4` from Bitbucket, you should start a container,
navigate to the `p4` folder, and type `chmod +x solutions/*.exe`.  This command
only needs to be run once.  It will make sure that certain files from the
assignment have their executable bit set.

## Assignment Details

Once we have an on-line service, one of the things we must be careful about is
how to ensure that it is not abused.  There are quite a few challenges in doing
so... what is a "fair" amount of use?  Should it vary by class of user?  How
strictly should a rule be enforced?  How much does it cost to enforce rules? And
for that matter, are some rules simply unenforceable (or impossible to enforce
*efficiently*)?

We will make four additions to the service in this assignment.  The first is to
add a `KVT` (TOP) command to the client and server.  `KVT` is like `KVA` from
assignment #2, except that the server will have a configurable threshold `T`,
and track the `T` most recently accessed keys.  `KVT` will return as many of
these keys as have not been deleted.  In this manner, supporting `KVT` will be
akin to maintaining an LRU cache of the hottest keys in the key/value store.  A
practical system might use such a cache to accelerate lookups (now you know why
YouTube advertisements load so much more quickly than the videos that follow!).
So, supposing that `G5` means "get key 5" and `R9` means "remove key 9", then if
`T` is 4 and we have the sequence `G6 G4 G5 G7 G6 R5`, then `KVT` should return
`6\n7\n4`.  That is, the second `G6` moves `6` *all the way to the front*, and
the presence of `R5` at the end means that we will will only have data for 3
elements, even though `T` is 4.

Our other three extensions will track the times of recent requests.  We will
enforce three quotas: download bandwidth, upload bandwidth, and number of
requests.  For download bandwidth, if a *user* requests more data (via `KVG`,
`KVA`, and `KVT`) in a time interval than the threshold allows, then
*subsequent* `KVG`, `KVA`, and `KVT` commands within the interval will result in
`ERR_QUOTA_DOWN`.  Similarly, both `KVU` and `KVI` will have their payloads
charged against an upload quota, and exceeding the quota will result in
`ERR_QUOTA_UP`.  Finally, every `KV?` operation will be counted against a user's
request-per-interval quota, and if the request rate exceeds the quota,
`ERR_QUOTA_REQ` will be returned.

Note that you will need to make sure that your management of quota information
is thread-safe, so that simultaneous requests from the same user cannot trick
your server.  Also, we will not persist quota information: restarting the server
resets all quotas.

## Getting Started

Your git repository has a new folder, `p4`, which contains a significant portion
of the code for the final solution to this assignment.  It also includes binary
files that represent much of the solution to assignment 3.  The `Makefile` has
been updated so that you do not need to have completed the first three
assignments in order to get full credit for this assignment.  In particular, you
will see that all code related to the authentication table is now available
through some "helper" methods, and thus the `scripts/p1.py` test script passes
without writing any new code.

There is a test script called `scripts/p4.py`, which you can use to test your
code.  These tests will help you to understand the expected behavior of the
server.

The new commands and API extensions have been added to `protocol.h`.  Note that
there are new possible errors for commands from Assignment #2.

## Tips and Reminders

Once you have one quota working, the others are likely to be pretty easy... so
the fastest way to getting a lot of points on this assignment is to create a
good data structure for managing quotas.

Ensuring that your management of quotas is thread safe is not easy.  You will
probably find that you need to chain together lambdas to get it to work.

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

While your solutions need to be thread-safe, we will not evaluate their
scalability.

## Grading

The `scripts` folder has four scripts that exercise the main portions of the
assignment: the MRU tracker, request quotas, upload quotas, and download quotas.
These scripts use specialized `Makefiles` that integrate some of the solution
code with some of your code, so that you can get partial credit when certain
portions of your code work.  Note that these `Makefiles` are very strict: they
will crash on any compiler warning.  You should *not* turn off the warnings;
they are there to help you.  If your code does not compile with the scripts, you
will not receive any credit.  If you have partial solutions and you do not know
how to coerce the code into being warning-free, you should ask the professor.

If the scripts pass, then you will receive full "functionality" points.  We
will manually inspect your code to determine if it is correct with regard to
atomicity.  As before, we reserve the right to deduct "style" points if your
code is especially convoluted.  Please be sure to use your tools well.  For
example, Visual Studio Code (and emacs, and vim) have features that auto-format
your code.  You should use these features.

While it is our intention to give partial credit, *no credit will be given for
code that does not compile without warnings.*  If you decide to move functions
between files, or add files, or do other things that break the scripts in the
grading folder, then you will lose at least 10%. If you think some change is
absolutely necessary, speak with the professor first.

There are three main graded portions of the assignment:

* Do KVT queries (top queries) track results correctly?
* Are the three quotas managed properly?
* Is threading handled correctly?

We are probably going to also check that your storage destructor is correct.

## Notes About the Reference Solution

You will need to make edits to three files in order to complete this assignment:
`server/my_storage.cc`, `server/my_mru.cc`, and `server/my_quota_tracker.cc`. If
you want to verify your code against the `scripts/p3.py` test, you will probably
want to use some of the helper functions from `persist.h` (we provide a `.o`
that implements those functions).

The reference solution to `my_mru.cc` is 85 lines.  It uses a `std::deque` as
its main data structure for tracking the most recently used elements.
Technically, it is possible to use a `std::vector`, but even for the `O(N)`
algorithms that we can use for this assignment, a vector would be slower.  You
should be sure you understand why (it has to do with erasing data).  Also, note
that for very large MRU caches, a `std::deque` would probably not have
satisfactory asymptotic performance.

The `my_quota_tracker.cc` reference solution is similarly short, consisting of
70 lines of code.  The solution uses the C/Unix `time` function to get the
system time, and stores it in a `time_t` object.  If you would rather use
something from `std::chrono`, that is fine.  Quota_tracker needs to maintain a
list of time/quantity pairs, in order to know when a quota has actually been
exceeded. A `std::deque` is a good choice for this data structure, for the same
reasons that it is good in `my_mru.cc`.  In fact, `std::deque` might even be the
optimal data structure choice for the quota tracker.

The reference solution adds 140 lines of code to `my_storage.cc`.  If you think
carefully about how quotas need to be checked, you will probably find that most
of this code is copy-and-paste.  It is possible to solve the assignment in fewer
lines.  When you work on this, please remember that all of the "key/value" tasks
need at least one quota check, and some need two.  You may decide that adding a
method to the `MyStorage` object makes it easier to re-use code.

## Collaboration and Getting Help

You may work in teams of 2 for this assignment.  If you plan to work in a team,
you must notify the instructor by November 5th, so that we can set up your
repository access.  If you notify us after that date, we will deduct 10 points.
If you wish to have a different team than in the last assignment, or to disband
your team and work alone, please contact the professor by November 5th. If you
are working in a team, you should **pair program** for the entire assignment.
After all, your goal is to learn together, not to each learn half the material.

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

You should be done with this assignment before 11:59 PM on November 21th, 2022.
Please be sure to `git commit` and `git push` before that time, so that we can
promptly collect and grade your work.
