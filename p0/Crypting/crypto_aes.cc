/**
 * crypto_aes.cc
 *
 * Crypto_aes demonstrates how to use symmetric AES encryption/decryption on a
 * chunk of data of arbitrary size.
 *
 * Note that AES keys are usually ephemeral: we make them, share them, use them
 * briefly, and discard them.  This demo saves an AES key to a file so that we
 * can convince ourselves that the program works, but in general, saving AES
 * keys is a bad practice.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <unistd.h>

/** size of AES key */
const int AES_256_KEY_SIZE = 32;

/** size of blocks that get encrypted... also size of IV */
const int BLOCK_SIZE = 16;

/** chunk size for reading/writing from files */
const int BUFSIZE = 1024;

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Perform basic AES encryption/decryption tasks.\n",
         basename(progname));
  printf("  -k [string] Name of the file holding the AES key\n");
  printf("  -i [string] Name of the input file to encrypt/decrypt\n");
  printf("  -o [string] Name of the output file to produce\n");
  printf("  -d          Decrypt from input to output using key\n");
  printf("  -e          Encrypt from input to output using key\n");
  printf("  -g          Generate a key file\n");
  printf("  -h       Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The file holding the AES key */
  std::string keyfile;

  /** The input file */
  std::string infile;

  /** The output file */
  std::string outfile;

  /** Should we decrypt? */
  bool decrypt = false;

  /** Should we encrypt? */
  bool encrypt = false;

  /** Should we generate a key? */
  bool generate = false;

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
  while ((opt = getopt(argc, argv, "k:i:o:degh")) != -1) {
    switch (opt) {
    case 'k':
      args.keyfile = std::string(optarg);
      break;
    case 'i':
      args.infile = std::string(optarg);
      break;
    case 'o':
      args.outfile = std::string(optarg);
      break;
    case 'd':
      args.decrypt = true;
      break;
    case 'e':
      args.encrypt = true;
      break;
    case 'g':
      args.generate = true;
      break;
    case 'h':
      args.usage = true;
      break;
    }
  }
}

int main(int argc, char **argv) {
  // Parse the command-line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // If the user requested the creation of an AES key, just make the key and
  // exit
  if (args.generate) {
    generate_aes_key_file(args.keyfile);
    return 0;
  }

  // Get the AES key from the file, and make an AES encryption context suitable
  // for either encryption or decryption
  EVP_CIPHER_CTX *ctx = get_aes_context(args.keyfile, args.encrypt);

  // Open the input and output files... Output file gets truncated
  FILE *infile = fopen(args.infile.c_str(), "rb");
  if (!infile) {
    perror("Error opening input file");
    EVP_CIPHER_CTX_cleanup(ctx);
    exit(0);
  }
  FILE *outfile = fopen(args.outfile.c_str(), "wb");
  if (!outfile) {
    perror("Error opening output file");
    EVP_CIPHER_CTX_cleanup(ctx);
    exit(0);
  }

  // Do the encryption or decryption.  Since it's symmetric, the call is the
  // same :)
  bool res = aes_crypt(ctx, infile, outfile);
  if (!res) {
    fprintf(stderr, "Error calling aes_crypt()");
  }
  fclose(infile);
  fclose(outfile);
  EVP_CIPHER_CTX_cleanup(ctx);
}

/**
 * Produce an AES key and save it to a file
 *
 * @param keyfile The name of the file to create
 */
void generate_aes_key_file(std::string keyfile) {
  // Generate an encryption key and initialization vector for AES, using a
  // cryptographically sound algorithm
  unsigned char key[AES_256_KEY_SIZE], iv[BLOCK_SIZE];
  if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
    fprintf(stderr, "Error in RAND_bytes()\n");
    exit(0);
  }

  // Create or truncate the key file
  FILE *file = fopen(keyfile.c_str(), "wb");
  if (!file) {
    perror("Error in fopen");
    exit(0);
  }

  // write key and iv to the file, and close it
  //
  // NB: we are ignoring errors here... good code wouldn't
  fwrite(key, sizeof(unsigned char), sizeof(key), file);
  fwrite(iv, sizeof(unsigned char), sizeof(iv), file);
  fclose(file);
}

/**
 * Produce an AES context that can be used for encrypting or decrypting.  Set
 * the AES key from the provided file.
 *
 * @param keyfile The name of the file holding the AES key
 * @param encrypt true if the context will be used to encrypt, false otherwise
 *
 * @return A properly configured AES context
 */
EVP_CIPHER_CTX *get_aes_context(std::string keyfile, bool encrypt) {
  // Open the key file and read the key and iv
  FILE *file = fopen(keyfile.c_str(), "rb");
  if (!file) {
    perror("Error opening keyfile");
    exit(0);
  }
  unsigned char key[AES_256_KEY_SIZE], iv[BLOCK_SIZE];
  int num_read = fread(key, sizeof(unsigned char), sizeof(key), file);
  num_read += fread(iv, sizeof(unsigned char), sizeof(iv), file);
  fclose(file);
  if (num_read != AES_256_KEY_SIZE + BLOCK_SIZE) {
    fprintf(stderr, "Error reading keyfile");
    exit(0);
  }

  // create and initialize a context for the AES operations we are going to do
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    fprintf(stderr, "Error: OpenSSL couldn't create context: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    exit(0);
  }

  // Make sure the key and iv lengths we have up above are valid
  if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr,
                         1)) {
    fprintf(stderr, "Error: OpenSSL couldn't initialize context: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    exit(0);
  }
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == BLOCK_SIZE);

  // Set the key and iv on the AES context, and set the mode to encrypt or
  // decrypt
  if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key, iv, encrypt ? 1 : 0)) {
    fprintf(stderr, "Error: OpenSSL couldn't re-init context: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    EVP_CIPHER_CTX_cleanup(ctx);
    exit(0);
  }

  return ctx;
}

/**
 * Take an input file and run the AES algorithm on it to produce an output file.
 * This can be used for either encryption or decryption, depending on how ctx is
 * configured.
 *
 * @param ctx A fully-configured symmetric cipher object for managing the
 *            encryption or decryption
 * @param in  the file to read
 * @param out the file to populate with the result of the AES algorithm
 */
bool aes_crypt(EVP_CIPHER_CTX *ctx, FILE *in, FILE *out) {
  // figure out the block size that AES is going to use
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));

  // Set up a buffer where AES puts crypted bits.  Since the last block is
  // special, we need this outside the loop.
  unsigned char out_buf[BUFSIZE + cipher_block_size];
  int out_len;

  // Read blocks from the file and crypt them:
  while (true) {
    // read from file
    unsigned char in_buf[BUFSIZE];
    int num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, in);
    if (ferror(in)) {
      perror("Error in fread()");
      return false;
    }
    // crypt in_buf into out_buf
    if (!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)) {
      fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
              ERR_error_string(ERR_get_error(), nullptr));
      return false;
    }
    // write crypted bytes to file
    fwrite(out_buf, sizeof(unsigned char), out_len, out);
    if (ferror(out)) {
      perror("Error in fwrite()");
      return false;
    }
    // stop on EOF
    if (num_bytes_read < BUFSIZE) {
      break;
    }
  }

  // The final block needs special attention!
  if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
    fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    return false;
  }
  fwrite(out_buf, sizeof(unsigned char), out_len, out);
  if (ferror(out)) {
    perror("Error in fwrite");
    return false;
  }
  return true;
}

