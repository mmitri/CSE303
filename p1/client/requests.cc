#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"

using namespace std;


/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(vector<uint8_t> &v, size_t sz){
  unsigned char buf[sz];
  if (RAND_bytes(buf, sz) != 1) {
    fprintf(stderr, "Error in RAND_bytes\n");
    return false;
  }
  v.insert(v.end(), &buf[0], &buf[sz]);
  return true;
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err_crypto(const vector<uint8_t> &v){
  string v_string(v.begin(), v.begin() + RES_ERR_CRYPTO.length());
  return v_string == RES_ERR_CRYPTO ? true : false;
}

bool is_err(const vector<uint8_t> &v){
  string v_string(v.begin(), v.begin() + 3);
  return v_string == "ERR" ? true : false;
}

/// If a buffer consists of OKbbbbd+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const std::vector<uint8_t> &buf, const string &filename){
  // Check to make sure the buffer is large enough for OK, 4 byte integer, and characters
  if (buf.size() < RES_OK.size() + 9){
    return;
  }
  //Check if the start of the buffer is "___OK___"
  if (string(buf.begin(), buf.begin() + RES_OK.size()) == RES_OK){
    // Get the size of the bytes to write to the file
    unsigned char buf2[8];
    memcpy(buf2, &buf[RES_OK.size()], 8); // Copy the next 4 bytes after "___OK___"
    int size = *(int*) buf2;
    if (size >= 0){
      // Write the bytes to the file
      FILE* file = fopen(filename.c_str(), "wb");
      if (!file){
        fprintf(stderr, "ERROR: Unable to open file\n");
        return;
      }
      int bytes_written = fwrite(&buf[RES_OK.size() + 8], sizeof(uint8_t), size, file);
      if (bytes_written != size){
        fprintf(stderr, "ERROR: Error writing to file\n");
        return;
      }
      fclose(file);
      cout << RES_OK << endl;
    }
  }
}

void addLenAsBytes(vector<uint8_t> &vec, long length){
  for(size_t i = 0; i < sizeof(long); i++){
    vec.push_back((length >> 8 * i) & 0xff);
  }
}

/// setAESBlock() puts bytes into the vector in the form of len(@u).@u.len(@p).@p.len(@w).@w o
/// @param vec the vector the bytes are going into
/// @param user the user name
/// @param pass the pass word
/// @param getUser the user to get the profile from (may be null)
void setupAESBlock(vector<uint8_t> &vec, const string &user, const string &pass){
  // Get lengths
  long userLength = (long) user.size();
  long passLength = (long) pass.size();
  // check if lengths are valid
  if (userLength > LEN_UNAME || passLength > LEN_PASSWORD){
    fprintf(stderr, "ERROR: Username or password is too long\n");
    exit(0);
  }
  //Add len(@u)
  addLenAsBytes(vec, userLength);
  //Add @u
  vec.insert(vec.end(), user.begin(), user.end());
  //Add len(@p)
  addLenAsBytes(vec, passLength);
  //Add @p
  vec.insert(vec.end(), pass.begin(), pass.end());
}

/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  // Create a uint8_t variable
  vector<uint8_t> reqKey(LEN_RKBLOCK);
  // Loop through the size of the uint8_t variable and pushback the string REQ_KEY
  for(size_t i=0;i<REQ_KEY.size(); i++){
    reqKey[i] = REQ_KEY[i];
  }
  
  // Write to the server
  int num_bytes_sent = send_reliably(sd, reqKey);
  if(num_bytes_sent <= 0){
    fprintf(stderr, "ERROR: Error writing req_key to server");
    exit(0);
  }
  // Receive bytes from server
  vector<uint8_t> pubkey(LEN_RSA_PUBKEY);
  int num_bytes_received = reliable_get_to_eof_or_n(sd, pubkey.begin(), LEN_RSA_PUBKEY);
  if (num_bytes_received <= 0){
    fprintf(stderr, "ERROR: Error receiving req_key response");
    exit(0);
  }

  // Write the pubkey to the file
  FILE* file = fopen(keyfile.c_str(), "wb");
  if (!file){
    fprintf(stderr, "ERROR: Unable to open pubkey file\n");
    return;
  }
  int bytes_written = fwrite(pubkey.data(), sizeof(uint8_t), LEN_RSA_PUBKEY, file);
  if (bytes_written != LEN_RSA_PUBKEY){
    fprintf(stderr, "ERROR: Error writing to pubkey file\n");
    return;
  }
  fclose(file);
}

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vector<uint8_t> send_cmd(int sd, RSA *pub, const string &cmd, const vector<uint8_t> &ablock){
  //initialize variables
  vector<uint8_t> rblock, encABlock;

  vector<uint8_t> aesKey = create_aes_key();
  encABlock = aes_crypt_msg(create_aes_context(aesKey, true), ablock);

  //Create and encrypt rBlock
  for(size_t i=0;i<cmd.size(); i++){
    rblock.push_back(cmd[i]);   //Add REQ_REG to beginning of rblock
  }
  rblock.insert(rblock.end(), aesKey.begin(), aesKey.end()); // Add .aeskey
  addLenAsBytes(rblock, (long) encABlock.size()); // Add len(@ablock)
  padR(rblock, LEN_RBLOCK_CONTENT - rblock.size());

  //Encrypt it into this buffer, with a size determined by the key
  vector<uint8_t> totalBlock(RSA_size(pub));
  int len = RSA_public_encrypt(rblock.size(), rblock.data(), totalBlock.data(), pub, RSA_PKCS1_OAEP_PADDING);
  if (len == -1) {
    fprintf(stderr, "Error encrypting\n");
    exit(0);
  }
  totalBlock.insert(totalBlock.end(), encABlock.begin(), encABlock.end());
  // Send bytes to server
  int num_bytes_sent = send_reliably(sd, totalBlock);
  if (num_bytes_sent <= 0){
    fprintf(stdout, "ERROR: Error sending req_reg to server");
    exit(0);
  }
  vector<uint8_t> response = reliable_get_to_eof(sd);
  if (response.size() == 0){
    fprintf(stdout, "ERROR: Error receiving req_key response");
    exit(0);
  }
  if(check_err_crypto(response)){
    fprintf(stdout, "ERROR: ERR_CRYPT returned from server");
    exit(0);
  }
  vector<uint8_t> decryptedResponse = aes_crypt_msg(create_aes_context(aesKey, false), response);
  if (is_err(decryptedResponse)){
    cout << string(decryptedResponse.begin(), decryptedResponse.end()) << endl;
    exit(0);
  }
  
  return decryptedResponse;
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_REG, ablock);
  cout << string(decryptedResponse.begin(), decryptedResponse.end()) << endl;
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_BYE, ablock);
  cout << string(decryptedResponse.begin(), decryptedResponse.end()) << endl;
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_SAV, ablock);
  cout << string(decryptedResponse.begin(), decryptedResponse.end()) << endl;
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  vector<uint8_t> file = load_entire_file(setfile);
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  addLenAsBytes(ablock, (long) file.size());
  ablock.insert(ablock.end(), file.begin(), file.end());
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_SET, ablock);
  cout << string(decryptedResponse.begin(), decryptedResponse.end()) << endl;
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  addLenAsBytes(ablock, (long) getname.size());
  ablock.insert(ablock.end(), getname.begin(), getname.end());
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_GET, ablock);
  send_result_to_file(decryptedResponse, string(getname + ".file.dat"));
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  vector<uint8_t> ablock; //Create and encrypt aBlock
  setupAESBlock(ablock, user, pass);
  vector<uint8_t> decryptedResponse = send_cmd(sd, pubkey, REQ_ALL, ablock);
  send_result_to_file(decryptedResponse, allfile);
}
