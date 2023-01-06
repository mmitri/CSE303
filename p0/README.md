# Assignment #0: C/C++ Warm-Up

The purpose of this assignment is to help you to refresh your skills in C/C++.

## Assignment Details

In CSE 303 / CSE 403: Operating Systems, our goal is to learn as much as
possible about the five core concepts in Operating Systems:

* Concurrency
* Persistence
* Resource Management
* Security
* Virtualization

We will learn about these five topics through both *theory* and *practice*.  For
the *theory* portion of our learning, we will read a textbook, have robust
conversations in class, and demonstrate the depth of our knowledge via quizzes.
For the *practice* portion of our learning, we will write code in C/C++ that
runs at a sufficiently low level that it enables us to get hands-on experience
with how these five topics manifest in real-world systems.

However, before we can have sophisticated interactions with our computer
systems, we need to be sure that we have a baseline understanding of how to
write correct low-level code.  To that end, in this assignment we will write a
handful of simple programs.  All of the guidance for writing these programs is
available online, in the tutorials at
`http://www.cse.lehigh.edu/~spear/cse303_tutorials/`.

These tutorials cover six important concepts:

* **Virtualization**: You will set up a Docker container for doing all of your
  development.  By using Docker, you will be guaranteed to have exactly the same
  development environment as the professor and TAs, so that you can be sure that
  when code works on your machine, it will work on ours.  This will also ensure
  that when code doesn't work on your machine, we will be able to reproduce the
  bug on our machine, so that we can help you figure out what's wrong.

* Basic C Programming: You will write code that does I/O to **persistent**
  files, and uses the standard C library.  You will also use some standard
  tools, like `make` and `git`.

* **Programmer Productivity**: You will start writing code that uses powerful
  features of C++, such as `lambdas`.  These features make it easier to write
  correct, maintainable, and extensible code.  Remember: low-level systems code
  can last for a decade or longer... maintainability is important!

* Networking and **Resource Management**: You will create several client/server
  programs, and learn how to use the Unix `screen` tool to multiplex your
  terminal.  You will also learn how to use the `select` system call to allow a
  single thread to serve multiple clients simultaneously and efficiently.

* **Concurrency**: You will learn how to use some of C++'s concurrency features,
  such as `threads`, `mutexes`, and `atomic` variables, to write a program that
  is capable of using multiple CPU cores, and communicating correctly among
  them.

* Encryption: You will use open-source libraries to encrypt data using the `RSA`
  and `AES` algorithms.  Through encryption, you will be able to **securely**
  store data, in a manner that cannot be compromised by an attacker.  (But
  remember: security is much more than just encryption!)

## Tips and Reminders

The entirety of this assignment is to do the tutorials at
`http://www.cse.lehigh.edu/~spear/cse303_tutorials/`.  If you are reading this
file, then you have already pulled the repository provided by the instructor.
You should do all of your work in the `p0` folder, and you should check in your
work every time you make progress.  Since you are working in an individual
repository, you should not hesitate to check in code when it has bugs, if you
feel that the code is worth saving (either because it has *fewer* bugs than it
used to, or because you want the professor or TAs to have a look).

The tutorials do not always give you all of the code at once.  Sometimes the
code is given out of order.  This also means that sometimes you will not be able
to compile and test your code until after completing several steps.

The tutorials should explain everything at a level of detail that is appropriate
for any student who successfully completed CSE 109.  If you find yourself having
trouble understanding anything, please use Piazza or recitations to get help.

**Start Early**.  These tutorials take time to read and understand.  If you were
to print the tutorials, they would come out to 80 pages!

Use `.gitignore` well.  It is possible to do all of the projects in this class
without having more than a few megabytes of files saved to your git repository.
But somehow, students find a way to consume hundreds of megabytes with compiler
output, core dumps, `.vscode` configuration, and other content that should never
be checked in.  Some of this material may contain sensitive information about
you, your accounts, or your computer configuration.  Be careful before you
commit.

When starting docker container instances, the `--rm` flag is very nice: it
automatically causes your container instance to be reclaimed as soon as the
container exits.

## Grading

This is an ungraded assignment.  However, you are strongly encouraged to do it.
And please note that "do" does not simply mean "copy and paste from the
tutorials".  You should try to understand every line of code that you write as
part of the tutorials.  It will be very hard to do well in the class if your
C/C++ programming skills are out of date.

## Collaboration and Getting Help

If you require help on this assignment, you may seek it from any of the
following sources:

* The professor and TAs, via office hours or Piazza
* Your classmates, either in person or through Piazza
* Current Lehigh students who have taken this course in the past

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.  Furthermore, in this
assignment, you should be able to learn everything you need from the above
resources.

## Deadline

You should be done with this assignment before the end of the day on September
2nd, 2022.  Please be sure to `git commit` and `git push` before that time, so
that we can see your progress.
