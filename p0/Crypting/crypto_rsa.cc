/**
 * crypto_rsa.cc
 *
 * Crypto_rsa demonstrates how to use public/private key RSA
 * encryption/decryption on a small chunk of data.
 *
 * Note that RSA keys are usually long-lived, so be sure to keep your private
 * key private!  Also, remember that RSA is slow, and often just used to sign a
 * digest or secure the transmission of an AES key that then gets used for the
 * actual encryption/decryption.
 */

#include <cassert>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string>
#include <unistd.h>

/** size of RSA key */
const int RSA_KEY_SIZE = 2048;

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Perform basic RSA encryption/decryption tasks.\n",
         basename(progname));
  printf("  -b [string] Name of the file holding the RSA public key\n");
  printf("  -v [string] Name of the file holding the RSA private key\n");
  printf("  -i [string] Name of the input file to encrypt/decrypt\n");
  printf("  -o [string] Name of the output file to produce\n");
  printf("  -d          Decrypt from input to output using key\n");
  printf("  -e          Encrypt from input to output using key\n");
  printf("  -g          Generate a key file\n");
  printf("  -h       Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The file holding the public RSA key */
  std::string pubkeyfile;

  /** The file holding the private RSA key */
  std::string prikeyfile;

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
  while ((opt = getopt(argc, argv, "b:v:i:o:degh")) != -1) {
    switch (opt) {
    case 'b':
      args.pubkeyfile = std::string(optarg);
      break;
    case 'v':
      args.prikeyfile = std::string(optarg);
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

int main(int argc, char *argv[]) {
  // Parse the command-line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  if (args.generate) {
    generate_rsa_key_files(args.pubkeyfile, args.prikeyfile);
    return 0;
  }

  // Open the input and output files... Output file gets truncated
  FILE *infile = fopen(args.infile.c_str(), "rb");
  if (!infile) {
    perror("Error opening input file");
    exit(0);
  }
  FILE *outfile = fopen(args.outfile.c_str(), "wb");
  if (!outfile) {
    perror("Error opening output file");
    exit(0);
  }

  // Encrypt or decrypt, and clean up
  if (args.encrypt) {
    printf("Encrypting %s to %s\n", args.infile.c_str(), args.outfile.c_str());
    RSA *pub = load_pub(args.pubkeyfile.c_str());
    if (rsa_encrypt(pub, infile, outfile)) {
      printf("Success!\n");
    }
    RSA_free(pub);
  } else if (args.decrypt) {
    printf("Decrypting %s to %s\n", args.infile.c_str(), args.outfile.c_str());
    RSA *pri = load_pri(args.prikeyfile.c_str());
    if (rsa_decrypt(pri, infile, outfile)) {
      printf("Success!\n");
    }
    RSA_free(pri);
  }
  fclose(infile);
  fclose(outfile);
}

/**
 * Print an error message and exit the program
 *
 * @param err The error code to return
 * @param msg The message to display
 */
void print_error_and_exit(int err, const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(err);
}

/**
 * Produce an RSA key and save its public and private parts to files
 *
 * @param pub The name of the public key file to generate
 * @param pri The name of the private key file to generate
 */
void generate_rsa_key_files(std::string pub, std::string pri) {
  printf("Generating RSA keys as (%s, %s)\n", pub.c_str(), pri.c_str());
  // When we create a new RSA keypair, we need to know the #bits (see constant
  // above) and the desired exponent to use in the public key.  The exponent
  // needs to be a bignum.  We'll use the RSA_F4 default value:
  BIGNUM *bn = BN_new();
  if (bn == nullptr) {
    print_error_and_exit(0, "Error in BN_set_word()");
  }
  if (BN_set_word(bn, RSA_F4) != 1) {
    BN_free(bn);
    print_error_and_exit(0, "Error in BN_set_word()");
  }

  // Now we can create the key pair
  RSA *rsa = RSA_new();
  if (rsa == nullptr) {
    BN_free(bn);
    print_error_and_exit(0, "Error in RSA_new()");
  }
  if (RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL) != 1) {
    BN_free(bn);
    RSA_free(rsa);
    print_error_and_exit(0, "Error in RSA_genreate_key_ex()");
  }

  // Create/truncate the files
  FILE *pubfile = fopen(pub.c_str(), "w");
  if (pubfile == nullptr) {
    BN_free(bn);
    RSA_free(rsa);
    perror("Error opening public key file for output");
    exit(0);
  }
  FILE *prifile = fopen(pri.c_str(), "w");
  if (prifile == nullptr) {
    BN_free(bn);
    RSA_free(rsa);
    fclose(pubfile);
    perror("Error opening private key file for output");
    exit(0);
  }

  // Perform the writes.  Defer cleanup on error, because the cleanup is the
  // same
  if (PEM_write_RSAPublicKey(pubfile, rsa) != 1) {
    fprintf(stderr, "Error writing public key\n");
  } else if (PEM_write_RSAPrivateKey(prifile, rsa, NULL, NULL, 0, NULL, NULL) !=
             1) {
    fprintf(stderr, "Error writing private key\n");
  } else {
    printf("Done\n");
  }

  // Cleanup regardless of whether the writes succeeded or failed
  fclose(pubfile);
  fclose(prifile);
  BN_free(bn);
  RSA_free(rsa);
}

/**
 * Load an RSA public key from the given filename
 *
 * @param filename The name of the file that has the public key in it
 */
RSA *load_pub(const char *filename) {
  FILE *pub = fopen(filename, "r");
  if (pub == nullptr) {
    perror("Error opening public key file");
    exit(0);
  }
  RSA *rsa = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL);
  if (rsa == nullptr) {
    print_error_and_exit(0, "Error reading public key file");
  }
  return rsa;
}

/**
 * Load an RSA private key from the given filename
 *
 * @param filename The name of the file that has the private key in it
 */
RSA *load_pri(const char *filename) {
  FILE *pri = fopen(filename, "r");
  if (pri == nullptr) {
    perror("Error opening private key file");
    exit(0);
  }
  RSA *rsa = PEM_read_RSAPrivateKey(pri, NULL, NULL, NULL);
  if (rsa == nullptr) {
    print_error_and_exit(0, "Error reading public key file");
  }
  return rsa;
}

/**
 * Encrypt a file's contents and write the result to another file
 *
 * @param pub The public key
 * @param in  The file to read
 * @param out The file to populate with the result of the encryption
 */
bool rsa_encrypt(RSA *pub, FILE *in, FILE *out) {
  // We're going to assume that the file is small, and read it straight into
  // this buffer:
  unsigned char msg[RSA_KEY_SIZE / 8] = {0};
  int bytes = fread(msg, 1, sizeof(msg), in);
  if (ferror(in)) {
    perror("Error in fread()");
    return false;
  }

  // Encrypt it into this buffer, with a size determined by the key
  unsigned char enc[RSA_size(pub)] = {0};
  int len = RSA_public_encrypt(bytes, msg, enc, pub, RSA_PKCS1_OAEP_PADDING);
  if (len == -1) {
    fprintf(stderr, "Error encrypting\n");
    return false;
  }

  // Write the result to the output file
  fwrite(enc, 1, len, out);
  if (ferror(out)) {
    perror("Error in fwrite()");
    return false;
  }
  return true;
}

/**
 * Decrypt a file's contents and write the result to another file
 *
 * @param pri The private key
 * @param in  The file to read
 * @param out The file to populate with the result of the encryption
 */
bool rsa_decrypt(RSA *pri, FILE *in, FILE *out) {
  // We're going to assume that the file is small, and read it straight into
  // this buffer:
  unsigned char msg[2 * RSA_KEY_SIZE / 8] = {0};
  int bytes = fread(msg, 1, sizeof(msg), in);
  if (ferror(in)) {
    perror("Error in fread()");
    return false;
  }

  // Decrypt it into this buffer, with a size determined by the key
  unsigned char dec[RSA_size(pri)] = {0};
  int len = RSA_private_decrypt(bytes, (unsigned char *)msg, dec, pri,
                                RSA_PKCS1_OAEP_PADDING);
  if (len == -1) {
    fprintf(stderr, "Error decrypting\n");
    return false;
  }

  // Write the result to the output file
  fwrite(dec, 1, len, out);
  if (ferror(out)) {
    perror("Error in fwrite()");
    return false;
  }
  return true;
}