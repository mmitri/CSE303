#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;

const int CMD_LENGTH = 8;

/// Helper method to check if the provided block of data is a kblock
///
/// @param block The block of data
///
/// @returns true if it is a kblock, false otherwise
bool is_kblock(const vector<uint8_t> &block){
  return string(block.begin(), block.begin() + REQ_KEY.size()) == REQ_KEY ? true : false;
}

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  // Read the rblock
  vector<uint8_t> rblock(LEN_RKBLOCK);
  int r_bytes_received = reliable_get_to_eof_or_n(sd, rblock.begin(), LEN_RKBLOCK);
  if (r_bytes_received <= 0){
    fprintf(stderr, "Error reading bytes in parsing.cc");
    cout << r_bytes_received << " Error reading rblock in parsing.cc\n";
    return true;
  }

  //Check if it's the kblock, if so, handle it with the handle_key() function
  if (is_kblock(rblock)){
    return handle_key(sd, pub);
  }
  else{
    // Decrypt it into this buffer, with a size determined by the key
    vector<uint8_t> dec_rblock(RSA_size(pri));
    int len = RSA_private_decrypt(rblock.size(), rblock.data(), dec_rblock.data(), pri, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
      fprintf(stderr, "Error decrypting\n");
      send_reliably(sd, RES_ERR_CRYPTO);
      return true;
    }

    //Get Request from first 8 bytes of decrypted msg
    string cmd = string(dec_rblock.begin(), dec_rblock.begin() + 8);
    //Get AES KEY from the next 48 bytes, 32 for the actual key, 16 for the initialization vector
    vector<uint8_t> aesKey;
    aesKey.insert(aesKey.end(), dec_rblock.begin() + CMD_LENGTH, dec_rblock.begin() + CMD_LENGTH + AES_KEYSIZE + AES_IVSIZE);
 
    //Get ablock length
    long length_ablock;
    memcpy(&length_ablock, dec_rblock.data() + CMD_LENGTH + AES_KEYSIZE + AES_IVSIZE, sizeof(long));
    //Get ablock
    vector<uint8_t> ablock(length_ablock);
    int a_bytes_received = reliable_get_to_eof_or_n(sd, ablock.begin(), length_ablock);
    if (a_bytes_received <= 0){
      fprintf(stderr, "Error reading bytes in parsing.cc");
      cout << "Error reading ablock in parsing.cc\n";
      return true;
    }
    //decrypt ablock
    vector<uint8_t> dec_ablock = aes_crypt_msg(create_aes_context(aesKey, false), ablock);
    if (dec_ablock.size() == 0){
      fprintf(stderr, "Error decrypting\n");
      send_reliably(sd, aes_crypt_msg(create_aes_context(aesKey, true), RES_ERR_CRYPTO));
      return true;
    }

    // Iterate through possible commands, pick the right one, run it
    vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
    decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav, handle_set, handle_get, handle_all};
    for (size_t i = 0; i < s.size(); ++i){
      if (cmd == s[i]){
        return cmds[i](sd, storage, create_aes_context(aesKey, true), dec_ablock);
      }
    }
    send_reliably(sd, aes_crypt_msg(create_aes_context(aesKey, true), RES_ERR_INV_CMD));
    return true;
  }
}
