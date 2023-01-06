/**
 * @file int_ops.cc
 * @author Mark Mitri (markmitri@pm.me) (markmitri.com)
 * @brief
 * Int_ops demostrates a few basic operations on an array of integers:
 * - creating integer arrays from a deterministic pseudo-random number generator.
 * - printing (text or binary)
 * - searching (linear or binary)
 * - sorting (via the C qsort() function)
 * 
 * NB: running this program with the -b flah and some nice large -n value is a
 *      good way to create binary data files for subsequent tutorials 
 * @version 0.1
 * @date 2022-08-21
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <utility>

/**
 * Display a help message to explain how the command-line parameters for this program work
 * 
 * @progname The name of the program
 */

void usage(char *int_ops){
    printf("%s: Demonstrate some basic operations on arrays of integers. \n", basename(int_ops));
    printf(" -n[int] Number of integers to put into an array\n");
    printf(" -r[int] Random seed to use when generating integers\n");
    printf(" -s     Sort the integer array?\n");
    printf(" -f[int] Find an integer in the array using binary search\n");
    printf(" -l[int] Find an integer in the array using linear search\n");
    printf(" -p     Print the array as text, with one int per line\n");
    printf(" -p     Print the array as text, with one int per line\n");
    printf(" -b     Print the array as binary\n");
    printf(" -h     Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t{
    /** The number of random elements to put into the array */
    unsigned num = 16;
    
    /** A random seed to use when generating elements to put into the array */
    unsigned seed = 0;

    /** Sort the array? */
    bool sort = false;

    /** Key to use for a binary search in the array */
    std::pair<bool,unsigned> bskey = {false, 0};

    /** Key to use for a linear search in the array */
    std::pair<bool, unsigned> lskey = {false, 0};

    /** Print the array as text? */
    bool printtext = false;

    /** Print the array as binary? */
    bool printbinary = false;

    /** Display a usage message? */
    bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args object.
 * 
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */

void parse_args(int argc, char **argv, arg_t &args){
    long opt;
    while((opt = getopt(argc, argv, "n:r:sf:l:pbh")) != -1){
        switch (opt){
            case 'n':
                args.num = atoi(optarg);
                break;
            case 'r':
                args.seed = atoi(optarg);
                break;
            case 's':
                args.sort = true;
                break;
            case 'f':
            // NB: C++ pair objects are a convenient way to store a tuple
                args.bskey = std::make_pair(true, atoi(optarg));
                break;
            case 'l':
                args.lskey = std::make_pair(true, atoi(optarg));
                break;
            case 'p':
                args.printtext = true;
                break;
            case 'b':
                args.printbinary = true;
                break;
            case 'h':
                args.usage = true;
                break;
        }
    }
}

/**
 * Create an array of the requested size, and populate it with randomly - generated integers
 * 
 * @param num The number of elements to put into the array
 * @param _seed The seed for the random-number generator 
 */
unsigned *create_array(unsigned num,unsigned _seed){
    //NB: we are using C-sytle allocation here, instead of 'new unsigned[num]'
    unsigned *arr = (unsigned *)malloc(num * sizeof(unsigned));
    if(arr == nullptr){
        char buf[1024];
        fprintf(stderr, "Error calling malloc: %s\n",
            strerror_r(errno, buf, sizeof(buf)));
        exit(0);
    }
    unsigned seed = _seed;
    for(unsigned i = 0; i < num; ++i){
        arr[i] = rand_r(&seed);
    }
    return arr;
}