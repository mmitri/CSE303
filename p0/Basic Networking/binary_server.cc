/**
 * @file binary_server.cc
 * @author Mark Mitri (markmitri@pm.me) (markmitri.com)
 * @brief Server side of the binary networking example
 * In our binary networking protocol, the client sends a number twice in a single message, and the server
 * increments the number and sends it back twice. If the client sends a zero, it means the communication is over. If the
 * client sends a -l, it means the server should shut down.
 * @version 0.1
 * @date 2022-08-26
 * 
 * @copyright Copyright (c) 2022. Adapted from http://www.cse.lehigh.edu/~spear/cse303_tutorials/#cse303_net.md
 * 
 */

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <errno.h>
#include <libgen.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

/**
 * @brief Display a help message to explain how the command-line parameters for this program work
 * 
 * @progname The name of the program
 */
void usage(char *progname){
    printf("%s: Server half of a client/server program to demostrate " "sending binary data over a network.\n", basename(progname));
    printf(" -p [int] Port number of the server\n");
    printf(" -h       Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t{
    /** The port on which the program will listen for connections */
    size_t port = 0;

    /** Is the user requesting a usage message? */
    bool usage = false;
};

/**
 * @brief Pase the command-line arguments, and use them to populate the provided args object.
 * 
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args){
    long opt;
    while((opt = getopt(argc, argv, "p:h")) != -1){
        switch(opt){
            case 'p':
                args.port = atoi(optarg);
                break;
            case 'h':
                args.usage = true;
                break;
        }
    }
}

int main(int argc, char *argv[]){
    // parse the command line arguments
    arg_t args;
    parse_args(argc, argv, args);
    if(args.usage){
        usage(argv[0]);
        exit(0);
    }

    // Set up the server socket for listening. This will exit the program on any error.
    int serverSd = create_server_socket(args.port);

    // We will keep going until we get a client who sends a -l as its first value
    bool keep_going = true;
    while(keep_going){
        // use accept() to wait for a client to connect
        printf("Waiting for a client to connect...\n");
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int connSd = accept(serverSd, (sockaddr *)&clientAddr, &clientAddrSize);
        if(connSd < 0){
            close(serverSd);
            error_on_message_and_exit(0, errno, "Error accepting request from client: ");
        }
        char clientname[1024];
        printf("Connected to %s\n", inet_ntop(AF_INET, &clientAddr.sin_addr, clientname, sizeof(clientname)));
        // NB: binary_server closes the connection before running
        keep_going = binary_server(connSd);
    }
    close(serverSd);
    return 0;
}