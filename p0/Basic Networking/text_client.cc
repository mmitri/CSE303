/**
 * @file text_client.cc
 * @author Mark Mitri (markmitri@pm.me) (markmitri.com)
 * @brief Text_client is half of a client/server pair that shows how to send text to a server and get a reply
 * @version 0.1
 * @date 2022-08-26
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

/**
 * @brief Display a help message to explain how the command-line parameters for this program work
 * 
 * @progname The name of the program
 */
void usage(char *progname){
    printf("%s: Client half of a client/server echo program to demonstrate " "sending text over a network.\n", basename(progname));
    printf(" -s [string] Name of the server (probably 'localhost')\n");
    printf(" -p [int] Port number of the server\n");
    printf(" -h       Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t{
    /** The name of the server to which the parent program will connect */
    std::string server_name = "";

    /** The port on which the program will connect to the above server */
    size_t port = 0;

    /** Is the user requesting a usage message? */
    bool usage = false;
};

/**
 * @brief Parse the command-line arguments, and use them to populate the provided args object.
 * 
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args){
    long opt;
    while((opt = getopt(argc, argv "p:s:h")) != -1){
        switch(opt){
            case 's':
                args.server_name = std::string(optarg);
                break;
            case 'p':
                args.port = atoi(optarg);
                break;
            case 'h':
                args.usage = true;
                break;
        }
    }
}