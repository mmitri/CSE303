#include <cassert>
#include <iostream>
#include <string>

#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

using namespace std;

/// Get the username from the request if it is a valid request
/// @param req the unencrypted request from the client
///
/// @return the username, or an empty string if the length is invalid
string getUserFromRequest(const vector<uint8_t> &req){
  long userLength;
  memcpy(&userLength, req.data(), sizeof(long));
  if (userLength > LEN_UNAME || userLength <= 0){
    fprintf(stderr, "ERROR: Invalid username length\n");
    return "";
  }
  return string(req.begin() + sizeof(long), req.begin() + sizeof(long) + userLength);
}

/// Get the password from the request if it is a valid request
/// @param req the unencrypted request from the client
/// @param userLength the length of the username
/// @return the password, or an empty string if the length is invalid
string getPassFromRequest(const vector<uint8_t> &req, const long userLength){
  long passLength;
  memcpy(&passLength, req.data() + sizeof(long) + userLength, sizeof(long));
  if (passLength > LEN_UNAME || passLength <= 0){
    fprintf(stderr, "ERROR: Invalid username length\n");
    return "";
  }
  return string(req.begin() + 2 * sizeof(long) + userLength, 
                req.begin() + 2 * sizeof(long) + userLength + passLength);
}

void addLenAsBytesToBeginning(vector<uint8_t> &vec, long length){
  vector<uint8_t> len;
  for(size_t i = 0; i < sizeof(long); i++){
    len.push_back((length >> 8 * i) & 0xff);
  }
  vec.insert(vec.begin(), len.begin(), len.end());
}

/// A commonly used function to respond once performing storage operation
/// Includes error checking for all function calls
/// @param sd The socket onto which the result should be written
/// @param ctx The AES encryption context
/// @param res The result of the storage operation
/// @return true if the server should halt, false if not
bool respond(int sd, EVP_CIPHER_CTX *ctx, Storage::result_t res){
  // Declaring outside of if-else block cause any request could fail
  bool bytes_sent;
  if (res.succeeded){
    // If there is data, format the request and send it
    if (res.data.size() != 0){
      addLenAsBytesToBeginning(res.data, (long)res.data.size());
      res.data.insert(res.data.begin(), res.msg.begin(), res.msg.end());
      bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, res.data));
    }
    //Else just send the message
    else{
      bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, res.msg));
    }
  }
  else{
    fprintf(stderr, "Error completing storage operation\n");
    bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, res.msg));
  }
  if (!bytes_sent){
    fprintf(stderr, "Error responding to client\n");
    cout << "Error responding to client\n";
    return true;
  }
  return false;
}

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  if (user == "" || pass == ""){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  // Add the user to the storage
  Storage::result_t res = storage->get_all_users(user, pass);

  return respond(sd, ctx, res);
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  //Get the length of the content
  long contentLength;
  // We can count the bytes we want because of the format
  memcpy(&contentLength, req.data() + 2*sizeof(long) + user.size() + pass.size(), sizeof(long));
  if (user == "" || pass == "" || contentLength <= 0 || contentLength >= LEN_PROFILE_FILE){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  vector<uint8_t> content;
  content.insert(content.end(), 
                  req.begin() + 3*sizeof(long) + user.size() + pass.size(),
                  req.begin() + 3*sizeof(long) + user.size() + pass.size() + contentLength);
  // Set the user data
  Storage::result_t res = storage->set_user_data(user, pass, content);
  //Send the response
  return respond(sd, ctx, res);
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  //Get the length of the username we're getting
  long getnameLength;
  // We can count the bytes we want because of the format
  memcpy(&getnameLength, req.data() + 2*sizeof(long) + user.size() + pass.size(), sizeof(long));
  if (user == "" || pass == "" || getnameLength <= 0 || getnameLength >= LEN_UNAME){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  string getname = string( 
                  req.begin() + 3*sizeof(long) + user.size() + pass.size(),
                  req.begin() + 3*sizeof(long) + user.size() + pass.size() + getnameLength);
  // Get the user data
  Storage::result_t res = storage->get_user_data(user, pass, getname);

  return respond(sd, ctx, res);
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  if (user == "" || pass == ""){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  // Add the user to the storage
  Storage::result_t res = storage->add_user(user, pass);

  return respond(sd, ctx, res);
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  bool bytes_sent = send_reliably(sd, pubfile);
  if(!bytes_sent){
    fprintf(stderr, "ERROR sending pubfile to client");
    cout << "ERROR sending pubfile to client\n";
    return true;
  }
  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  if (user == "" || pass == ""){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  Storage::result_t res = storage->auth(user, pass);
  respond(sd, ctx, res);
  return res.succeeded;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  //Get the user name and password from the request
  //Send out req format error if invalid
  string user = getUserFromRequest(req);
  string pass = getPassFromRequest(req, user.size());
  if (user == "" || pass == ""){
    bool bytes_sent = send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
    if (!bytes_sent){
      fprintf(stderr, "Error responding to client\n");
      return true;
    }
  }
  Storage::result_t res = storage->auth(user, pass);
  if (res.succeeded){
    Storage::result_t res2 = storage->save_file();
    return respond(sd, ctx, res2);
  }
  else{
    return respond(sd, ctx, res);
  }
}
