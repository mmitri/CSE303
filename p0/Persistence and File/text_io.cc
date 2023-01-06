/**
 * @file text_io.cc
 * @author Mark Mitri (markmitri@pm.me) (markmitri.com)
 * @brief 
 * Text_io is similar to the Unix cat utility: it reads bytes from one file
 * and writes them to another. By default, it reads stdin and writes stdout, but
 * it can be configured to open files to serve as input and/or output. It also
 * supports appending. Finally, it allows for the input and/or output files to
 * be accessed as C file streams or Unix file descriptors.
 * @version 0.1
 * @date 2022-08-25
 * 
 * @copyright Copyright (c) 2022. Adapted from http://www.cse.lehigh.edu/~spear/cse303_tutorials/#cse303_textio.md
 * 
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <libgen.h>
#include <string>
#include <unistd.h>

/**
 * @brief 
 * Display a help message to explain how the command-line parameters for this program work
 * 
 * @progname The name of the program
 */
void usage(char *progname){
    printf("%s: Demonstrate text-based I/O with streams and file descriptors.\n", basename(progname));
    printf("  -i        Use file descriptor instead of stream for input file\n");
    printf("  -I [file] Specify a file to use for input, instead of stdin\n");
    printf("  -o        Use file descriptor instead of stream for output file\n");
    printf("  -O [file] Specify a file to use for output, instead of stdout\n");
    printf("  -a        Open output file in append mode (only works with -O)\n");
    printf("  -h        Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t{
    /** should we use streams (FILE*) or file descriptions (int), for input */
    bool in_fd = false;

    /** should we use streams (FILE*) or file descriptions (int), for output */
    bool out_fd = false;

    /** filename to open (instead of stdin) for input */
    std::string in_file = "";

    /** filename to open (instead of stdout) for output */
    std::string out_file = "";

    /** append to output file? */
    bool append = false;

    /** Is the user requesting a usage message? */
    bool usage = false;
};

/**
 * @brief 
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 * 
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args){
    long opt;
    while ((opt = getopt(argc, argv, "aioI:O:h")) != 1){
        switch(opt){
            case 'a':
                args.append = true;
                break;
            case 'i':
                args.in_fd = true;
                break;
            case 'o':
                args.out_fd = true;
                break;
            case 'I':
                args.in_file = std::string(optarg);
                break;
            case 'O':
                args.out_file = std::string(optarg);
                break;
            case 'h':
                args.usage = true;
                break;
        }
    }
}

/**
 * @brief Read text from a file stream and pass it to a callback function
 * 
 * @param file The file stream to read from
 * @param cb A callback function that operated on each line of text read from the stream.
 *           It expects to take a pointer to some tet, and the number of valid bytes reachable from that pointer.
 */
void read_lines_file(FILE *file, std::function<void(const char*, size_t)>cb){
    // read data into this space on the stack
    char buffer[16];

    // NB: fgets() will read at most sizeof(line)-1 bytes, so that it can add a \0
    //     as the last character (so that printf and friends will work)
    // NB: fgets() returns nullptr on either EOF or an error. We will treat
    //     errors as a reason to stop reading
    // NB: we don't always get a full 16 bytes on a fgets, so the callback can't
    //     write '\n'. Instead, it must print the '\n' characters that come from the input.
    while (fgets(buffer, sizeof(buffer), file)){
        cb(buffer, strlen(buffer));
    }
    // now check for an error before closing the file/
    if(ferror(file)){
        perror("read_lines_file::fgets()");
        // for errors on FILE*, we must clear the error when we are done handling it
        clearerr(file);
    }
}

/**
 * @brief Write text to a file stream
 * NB: Since we are assuming that we will recieve text, we are assuming that the 
 *     provided buffer will be null-terminated. Thus there is no need to use the provided buffer size
 * 
 * @param file The file stream to write to
 * @param buffer The buffer of text to write to the stream
 * @param num The number of bytes in the buffer (ignored)
 */
void write_file(FILE *file, const char *buffer, size_t num){
    // if fputs() returns EOF, there was an error, so print it, then clear it
    if(fputs(buffer, file) == EOF){
        perror("write_file::fputs()");
        clearerr(file);
    }
}

/**
 * @brief Read text from a file descriptor and pass it to a callback function
 * 
 * @param fd The file descriptor to read from
 * @param cd A callback function that operates on each line of text provided by the user.
 *           It expects to take a pointer to some text, and the number of valid bytes reachable from that pointer.
 */
void read_lines_fd(int fd, std::function<void(const char *, size_t)>cb){
    // read data into this space on the stack
    char buffer[12];

    // NB: read() may read as many bytes as we let it, and will not put a \0 at the end,
    //     so we will need to do that manually.
    // NB: read() returns the number of bytes read. 0 means EOF. Negative means
    //     error. It will not always read the maximum possible, so be sure to check.
    //     We will treat errors as a reason to stop reading.
    // NB: if fd refers to a true file, then all errors are bad. But if fd refers
    //     to a network socket, then an EINTR error is actually ok, and we should keep reading.
    //     If you are reading from a socket, the below loop is not correct.
    ssize_t bytes_read;
    while((bytes_read = read(fd, buffer, sizeof(buffer) -1)) > 0){
        // we read one less byte than we could, so that we can put a zero at the end.
        // This is necessary because we *might* be calling back to something that expects
        // a null-terminated string. Were it not for this next line, we could use this function
        // to read binary and text data from the file descriptor.
        buffer[bytes_read] = '\0';
        // NB: do not include the trailing null in the number of bytes to callback
        cb(buffer,bytes_read);
    }
    // now check for an error before closing the file
    if(bytes_read < 0){
        perror("read_lines_fd::read()");
    }
}

/**
 * @brief Write data (not exclusively text) to a file stream
 * 
 * @param fd The file descriptor to write to
 * @param buffer The buffer of data to write to the stream
 * @param num The number of bytes in the buffer
 */
void write_fd(int fd, const char *buffer, size_t num){
    // as with read(), we may not write as many bytes as we intend, so we need to track
    // how many bytes have been written, and where to resume writing if we
    // have bytes left to write.
    size_t bytes_written = 0;
    const char *next_byte = buffer;
    while(bytes_written < num){
        ssize_t bytes = write(fd, next_byte, num - bytes_written);
        // negative bytes writted indicates an error
        if(bytes < 0){
            // NB: erros on file descriptors do not need to be cleared
            perror("write_fd::write()");
            // NB: as with read(), if fd is a socket, then we should be checking for
            //     EINTR and continuing when the error is EINTR
            return;
        }else{ // otherwise, advance forward to the next bytes to write
            bytes_written += bytes;
            next_byte += bytes;
        }
    }
}

int main(int argc, char **argv){
    arg_t args;
    parse_args(argc, argv, args);

    // if help was requested, give help, then quit
    if(args.usage){
        usage(argv[0]);
        return 0;
    }

    // setup default input file
    FILE *in_stream = stdin;
    int in_fd = fileno(stdin);

    // setup default output file
    FILE *out_stream = stdout;
    int out_fd = fileno(stdout);

    // Should we open an input file? If so, do it in read-only mode.
    if(args.in_file != ""){
        in_stream = fopen(args.in_file.c_str(), "r");
        if(in_stream == nullptr){
            perror("fopen(in_file)");
            return -1;
        }
        in_fd = open(args.in_file.c_str(), O_RDONLY);
        if(in_fd < 0){
            perror("open(in_file)");
            return -1;
        }
    }

    // Should we open an output file? If so, should it be write-only or
    // append-only? Note that the file mode will be 700
    if (args.out_file != ""){
        out_stream = fopen(args.out_file.c_str(), args.append ? "a":"w");
        if(out_stream == nullptr){
            perror("fopen(out_file)");
            return -1;
        }
        if(args.append){
            out_fd = open(args.out_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
        }else{
            out_fd = open(args.out_file.c_str(), O_WRONLY | O_CREAT, S_IRWXU);
        }
        if(out_fd < 0){
            perror("open(out_file)");
            return -1;
        }
    }

     // Create C++ lambdas to hide differences between writing to a stream and
  // writing to a file descriptor.
  std::function<void(const char *, size_t)> print_stream =
      [&](const char *buf, size_t num) { write_file(out_stream, buf, num); };
  std::function<void(const char *, size_t)> print_fd =
      [&](const char *buf, size_t num) { write_fd(out_fd, buf, num); };

  // Dispatch to the file descriptor or stream version of reading, and pass the
  // appropriate writing function
  if (args.in_fd) {
    read_lines_fd(in_fd, args.out_fd ? print_fd : print_stream);
  } else {
    read_lines_file(in_stream, args.out_fd ? print_fd : print_stream);
  }

  // only close the input file if it wasn't stdin
  if (args.in_file != "") {
    if (close(in_fd) < 0) {
      perror("close(in_fd)");
    }
    if (fclose(in_stream) < 0) {
      perror("fclose(in_stream)");
    }
  }

  // only close the output file if it wasn't stdout
  if (args.out_file != "") {
    if (close(out_fd) < 0) {
        perror("close(out_fd)");
    }
    if (fclose(out_stream) < 0) {
        perror("fclose(out_stream)");
        }
    }
}