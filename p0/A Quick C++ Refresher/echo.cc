/**
 * echo.cc
 *
 * Echo receives text from stdin and writes it to stdout. Remember that by
 * running this program and using I/O redirection ('>file' to redirect stdout to
 * a file, and '<file' to redirect stdin to a file), it is possible to use this
 * program to stream keystrokes to a file, or to display an existing file
 * similar to the 'cat' command.
 */

#include <cstdio>

int main(){
    //we will read data into this space on the stack. It can be any size, but
    //we will do 16 bytes at a time.
    char buffer[16];

    // NB: While it's tempting to use scanf() or cin to read from stdin, they
    //     will parse the input and only read one thing (text word, integer, etc).
    //     If we want to read all of the user's input exactly, we can't use
    //     something that will treat consecutive whitespace as a word boundary, so
    //     instead we need to use something from the "get" family.  One should
    //     NEVER use 'gets()', because it does not bound how much data is read,
    //     and we always must read into a buffer of bounded size.  Much better is
    //     to use fgets, which takes a pointer to a buffer, the size of the
    //     buffer, and a file stream (in our case stdin).

    // NB: fgets() will read at most sizeof(buffer)-1 bytes, so that it can add a
    //     \0 as the last character (so that printf-style functions will work)
    //
    // NB: We should be paying attention to errors from fgets, but in this program
    //     we don't.  This program represents the last time we are allowed to
    //     ignore errors in this tutorial series.
    while(fgets(buffer,sizeof(buffer),stdin)){
        // NB: THis version of printf is effectively 'fputs(buffer,stdout)'
        //
        // NB: We are ignoring the return value from printf(). The tutorial series
        // will limit uses of printf() so that we can always ignore printf()
        // errors
        printf("%s", buffer);
    }
}