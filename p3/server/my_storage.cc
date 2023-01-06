#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"


#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

  /// The open file
  FILE *storage_file = nullptr;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    // Create the salt
    vector<uint8_t> salt;
    unsigned char buf[LEN_SALT];
    if (RAND_bytes(buf, LEN_SALT) != 1) {
      fprintf(stderr, "Error in RAND_bytes\n");
      return {false, RES_ERR_SERVER, {}};
    }
    salt.insert(salt.end(), &buf[0], &buf[LEN_SALT]);

    // Add the salt to the password
    vector<uint8_t> saltedPass;
    saltedPass.insert(saltedPass.end(), pass.begin(), pass.end());
    saltedPass.insert(saltedPass.end(), salt.begin(), salt.end());

    // Hash the salted password
    vector<uint8_t> hash(LEN_PASSHASH);
    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) <= 0
      || SHA256_Update(&sha256, saltedPass.data(), saltedPass.size()) <= 0
      || SHA256_Final(hash.data(), &sha256) <= 0){
        return {false, RES_ERR_SERVER, {}};
    }

    // Add auth table entry
    AuthTableEntry entry;
    entry.username = user; entry.pass_hash = hash;
    entry.salt = salt; entry.content = {};

    //Define the lambda function to write a user to the persist file on success
    auto write_user_to_file = [&](){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant AUTHAUTH
      buf.insert(buf.end(), AUTHENTRY.begin(), AUTHENTRY.end());
      /// - 8-byte binary write of the length of the username
      addLenAsBytes(buf, (long) entry.username.size());
      /// - Binary write of the bytes of the username
      buf.insert(buf.end(), entry.username.begin(), entry.username.end());
      /// - 8-byte binary write of the length of the salt
      addLenAsBytes(buf, (long) entry.salt.size());
      /// - Binary write of the bytes of the salt
      buf.insert(buf.end(), entry.salt.begin(), entry.salt.end());
      /// - 8-byte binary write of the length of the hashed password
      addLenAsBytes(buf, (long) entry.pass_hash.size());
      /// - Binary write of the bytes of the hashed password
      buf.insert(buf.end(), entry.pass_hash.begin(), entry.pass_hash.end());
      /// - 8-byte binary write of the length of the profile file
      addLenAsBytes(buf, (long) entry.content.size());
      if (entry.content.size() > 0){
        /// - If the profile file isn't empty, binary write of the bytes of the profile file
        buf.insert(buf.end(), entry.content.begin(), entry.content.end());
      }
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole auth table entry to file\n";
      }

      fflush(storage_file);
    };
    if (auth_table->insert(user, entry, write_user_to_file)){
      return {true, RES_OK, {}};
    }
    else{
      return {false, RES_ERR_USER_EXISTS, {}};
    }
    return {false, RES_ERR_SERVER, {}};
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    result_t res = auth(user, pass);
    if (res.succeeded){
      // Set user content and write the update to the fiile
      auto set_content = [&](AuthTableEntry &a){ 
        a.content = content;
        /// Lambda function to add the length of the vector as bytes to the input vector
        auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
          for(size_t i = 0; i < sizeof(long); i++){
            vec.push_back((len >> 8 * i) & 0xff);
          }
        };
        //Format the entry according to format.h
        vector<uint8_t> buf;
        /// - 8-byte constant AUTHDIFF
        buf.insert(buf.end(), AUTHDIFF.begin(), AUTHDIFF.end());
        /// - 8-byte binary write of the length of the username
        addLenAsBytes(buf, (long) a.username.size());
        /// - Binary write of the bytes of the username
        buf.insert(buf.end(), a.username.begin(), a.username.end());
        /// - 8-byte binary write of the length of the profile file
        addLenAsBytes(buf, (long) content.size());
        if (content.size() > 0){
          /// - If the profile file isn't empty, binary write of the bytes of the profile file
          buf.insert(buf.end(), content.begin(), content.end());
        }
        /// - Binary write of some bytes of padding, to ensure that the next entry will
        ///   be aligned on an 8-byte boundary.
        while (buf.size() % 8 != 0){
          buf.push_back('\0');
        }

        size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
        if (num_bytes_written != buf.size()){
          cout << "Failed to write whole auth table diff to file\n";
        }
        fflush(storage_file); // flush for persistence
      };
      if(auth_table->do_with(user, set_content)){
        return {true, RES_OK, {}};
      }
      else{
        return {false, RES_ERR_LOGIN, {}};
      }
    }
    else{
      return res;
    }
    return {false, RES_ERR_SERVER, {}};
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    result_t res = auth(user, pass);
    if (res.succeeded){
      // Get user content from auth table
      vector<uint8_t> content;
      auto get_content = [&content](AuthTableEntry a){ content = a.content; };
      if(auth_table->do_with_readonly(who, get_content)){
        if (content.size() > 0){
          return {true, RES_OK, content};
        }
        else{
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        return {false, RES_ERR_NO_USER, {}};
      }
    }
    else{
      return res;
    }
    return {false, RES_ERR_SERVER, {}};
  }


  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    result_t res = auth(user, pass);
    if (res.succeeded){
      // Get all user content from auth table
      vector<uint8_t> content;
      auto get_content = [&content](string k, AuthTableEntry a){ 
        content.insert(content.end(), k.begin(), k.end());
        content.push_back('\n');
        //Assert to hide compiler warning
        assert(a.content.size() > 0);
      };
      auto then = [](){};
      auth_table->do_all_readonly(get_content, then);
      return {true, RES_OK, content};
    }
    else{
      return res;
    }
    return {false, RES_ERR_SERVER, {}};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
     // Get user from auth table
    AuthTableEntry userData;
    auto get_user = [&userData](AuthTableEntry a){ userData = a; };
    if(!auth_table->do_with_readonly(user, get_user)){
      return {false, RES_ERR_LOGIN, {}};
    }
    
    // Salt the password
    vector<uint8_t> saltedPass;
    saltedPass.insert(saltedPass.end(), pass.begin(), pass.end());
    saltedPass.insert(saltedPass.end(), userData.salt.begin(), userData.salt.end()); 

    // Hash the salted password
    vector<uint8_t> hash(LEN_PASSHASH);
    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) <= 0
      || SHA256_Update(&sha256, saltedPass.data(), saltedPass.size()) <= 0
      || SHA256_Final(hash.data(), &sha256) <= 0){
        return {false, RES_ERR_SERVER, {}};
    }

    // Check if the hash matches the user's hash
    // comparing two vectors with == does work, it will compare the entire vector
    if (hash == userData.pass_hash){
      return {true, RES_OK, {}};
    }
    else{
      return {false, RES_ERR_LOGIN, {}};
    }

    return {false, RES_ERR_SERVER, {}};
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto r = auth(user, pass);
    if (!r.succeeded)
      return {false, r.msg, {}};
    // Lambda function to persist the insert to log file 
    auto write_kv_to_file = [&](){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant KVKVKVKV
      buf.insert(buf.end(), KVENTRY.begin(), KVENTRY.end());
      /// - 8-byte binary write of the length of the key
      addLenAsBytes(buf, (long) key.size());
      /// - Binary write of the bytes of the key
      buf.insert(buf.end(), key.begin(), key.end());
      /// - 8-byte binary write of the length of the value
      addLenAsBytes(buf, (long) val.size());
      /// - Binary write of the bytes of the value
      buf.insert(buf.end(), val.begin(), val.end());
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole kv entry to file\n";
      }

      fflush(storage_file);
    };
    if (kv_store->insert(key, vector(val), write_kv_to_file)) 
      return {true, RES_OK, {}};
    return {false, RES_ERR_KEY, {}};
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {
    result_t res = auth(user, pass);
      if (res.succeeded){
        // Get user content from auth table
        vector<uint8_t> content;
        auto get_content = [&content](vector<uint8_t> val){ content = val; };
        if(kv_store->do_with_readonly(key, get_content)){
          if (content.size() > 0){
            return {true, RES_OK, content};
          }
          else{
            return {false, RES_ERR_NO_DATA, {}};
          }
        }
        else{
          return {false, RES_ERR_KEY, {}};
        }
      }
      else{
        return res;
      }
      return {false, RES_ERR_SERVER, {}};
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    auto r = auth(user, pass);
    if (!r.succeeded)
      return {false, r.msg, {}};
    // Lambda function to persist the delete to log file 
    auto write_kv_delete_to_file = [&](){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant KVDELETE
      buf.insert(buf.end(), KVDELETE.begin(), KVDELETE.end());
      /// - 8-byte binary write of the length of the key
      addLenAsBytes(buf, (long) key.size());
      /// - Binary write of the bytes of the key
      buf.insert(buf.end(), key.begin(), key.end());
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole kv delete entry to file\n";
      }

      fflush(storage_file);
    };
    if (kv_store->remove(key, write_kv_delete_to_file))
      return {true, RES_OK, {}};
    return {false, RES_ERR_KEY, {}};
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto r = auth(user, pass);
    if (!r.succeeded)
      return {false, r.msg, {}};
    // Lambda function to persist the insert to log file 
    auto write_kv_to_file = [&](){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant KVKVKVKV
      buf.insert(buf.end(), KVENTRY.begin(), KVENTRY.end());
      /// - 8-byte binary write of the length of the key
      addLenAsBytes(buf, (long) key.size());
      /// - Binary write of the bytes of the key
      buf.insert(buf.end(), key.begin(), key.end());
      /// - 8-byte binary write of the length of the value
      addLenAsBytes(buf, (long) val.size());
      /// - Binary write of the bytes of the value
      buf.insert(buf.end(), val.begin(), val.end());
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole kv entry to file\n";
      }

      fflush(storage_file);
    };

    // Lambda function to persist the insert to log file 
    auto write_kv_update_to_file = [&](){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant KVUPDATE
      buf.insert(buf.end(), KVUPDATE.begin(), KVUPDATE.end());
      /// - 8-byte binary write of the length of the key
      addLenAsBytes(buf, (long) key.size());
      /// - Binary write of the bytes of the key
      buf.insert(buf.end(), key.begin(), key.end());
      /// - 8-byte binary write of the length of the value
      addLenAsBytes(buf, (long) val.size());
      /// - Binary write of the bytes of the value
      buf.insert(buf.end(), val.begin(), val.end());
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), storage_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole kv entry to file\n";
      }

      fflush(storage_file);
    };


    if (kv_store->upsert(key, vector(val), write_kv_to_file, write_kv_update_to_file))
      return {true, RES_OKINS, {}};
    return {true, RES_OKUPD, {}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    result_t res = auth(user, pass);
    if (res.succeeded){
      // Get all user content from auth table
      vector<uint8_t> content;
      auto get_content = [&content](string k, vector<uint8_t> val){ 
        content.insert(content.end(), k.begin(), k.end());
        content.push_back('\n');
        //Assert to hide compiler warning
        assert(val.size());
      };
      auto then = [](){};
      kv_store->do_all_readonly(get_content, then);
      if (content.size() == 0){
        return {false, RES_ERR_NO_DATA, {}};
      }
      return {true, RES_OK, content};
    }
    else{
      return res;
    }
    return {false, RES_ERR_SERVER, {}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    if (fclose(storage_file) != 0){
      cout << "Error shutting down\n";
    }
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // Open the temp file
    string tempfilename = filename + ".tmp";
    FILE* temp_file = fopen(tempfilename.c_str(), "w");
    // Define the lambda function to write a user
    auto write_user_to_file = [&temp_file](string key, AuthTableEntry val){
      /// Lambda function to add the length of the vector as bytes to the input vector
      auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
        for(size_t i = 0; i < sizeof(long); i++){
          vec.push_back((len >> 8 * i) & 0xff);
        }
      };
      //Format the entry according to format.h
      vector<uint8_t> buf;
      /// - 8-byte constant AUTHAUTH
      buf.insert(buf.end(), AUTHENTRY.begin(), AUTHENTRY.end());
      /// - 8-byte binary write of the length of the username
      addLenAsBytes(buf, (long) key.size());
      /// - Binary write of the bytes of the username
      buf.insert(buf.end(), key.begin(), key.end());
      /// - 8-byte binary write of the length of the salt
      addLenAsBytes(buf, (long) val.salt.size());
      /// - Binary write of the bytes of the salt
      buf.insert(buf.end(), val.salt.begin(), val.salt.end());
      /// - 8-byte binary write of the length of the hashed password
      addLenAsBytes(buf, (long) val.pass_hash.size());
      /// - Binary write of the bytes of the hashed password
      buf.insert(buf.end(), val.pass_hash.begin(), val.pass_hash.end());
      /// - 8-byte binary write of the length of the profile file
      addLenAsBytes(buf, (long) val.content.size());
      if (val.content.size() > 0){
        /// - If the profile file isn't empty, binary write of the bytes of the profile file
        buf.insert(buf.end(), val.content.begin(), val.content.end());
      }
      /// - Binary write of some bytes of padding, to ensure that the next entry will
      ///   be aligned on an 8-byte boundary.
      while (buf.size() % 8 != 0){
        buf.push_back('\0');
      }

      size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), temp_file);
      if (num_bytes_written != buf.size()){
        cout << "Failed to write whole auth table entry to file\n";
      }
    };

    auto thenWriteKv = [&](){
      auto write_kv_to_file = [&](string key, vector<uint8_t> val){
        /// Lambda function to add the length of the vector as bytes to the input vector
        auto addLenAsBytes = [](vector<uint8_t> &vec, long len){
          for(size_t i = 0; i < sizeof(long); i++){
            vec.push_back((len >> 8 * i) & 0xff);
          }
        };
        //Format the entry according to format.h
        vector<uint8_t> buf;
        /// - 8-byte constant AUTHAUTH
        buf.insert(buf.end(), KVENTRY.begin(), KVENTRY.end());
        /// - 8-byte binary write of the length of the key
        addLenAsBytes(buf, (long) key.size());
        /// - Binary write of the bytes of the key
        buf.insert(buf.end(), key.begin(), key.end());
        /// - 8-byte binary write of the length of the value
        addLenAsBytes(buf, (long) val.size());
        /// - Binary write of the bytes of the value
        buf.insert(buf.end(), val.begin(), val.end());
        /// - Binary write of some bytes of padding, to ensure that the next entry will
        ///   be aligned on an 8-byte boundary.
        while (buf.size() % 8 != 0){
          buf.push_back('\0');
        }

        size_t num_bytes_written = fwrite(buf.data(), sizeof(uint8_t), buf.size(), temp_file);
        if (num_bytes_written != buf.size()){
          cout << "Failed to write whole kv entry to file\n";
        }
      };
      auto then = [](){};
      kv_store->do_all_readonly(write_kv_to_file, then);
    };

    auth_table->do_all_readonly(write_user_to_file, thenWriteKv);
    // After the function applies to all, then rename the temp file to the new file
    rename(tempfilename.c_str(), filename.c_str());
    fclose(temp_file);
    return {true, RES_OK, {}};
  }

  void getLenThenReadToVec(vector<uint8_t>::const_iterator &iterator, vector<uint8_t> &vec, long maxlength){
    // This seems like a weird way to get the length from the iterator
    // but I couldn't get anything else to work
    vector<uint8_t> length_bytes;
    length_bytes.insert(length_bytes.end(), iterator, iterator + 8);
    long length;
    memcpy(&length, length_bytes.data(), sizeof(long));
    iterator += sizeof(long);
    if (length > 0 && length <= maxlength){
      vec.insert(vec.end(), iterator, iterator + length);
      iterator += length;
    }
    else{
      // If the length is 0, that is fine as long as it's the profile content
      if (maxlength == LEN_PROFILE_FILE && length == 0){
        return;
      }
      cout << "ERROR parsing in load_file\n";
    }
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    // Clear maps
    auth_table->clear();
    kv_store->clear();

    // load file just like load_entire_file() does in file.h, but
    // save the pointer in storage_file and don't close it
    struct stat stat_buf;
    if (stat(filename.c_str(), &stat_buf) != 0){
      storage_file = fopen(filename.c_str(), "a+");
      return {true, "File not found: " + filename, {}};
    }
    storage_file = fopen(filename.c_str(), "a+");
    if (!storage_file){
      return {true, "File not found: " + filename, {}};
    }
    // reserve space in vec, based on stat() from before open() (TOCTOU risk)
    vector<uint8_t> file_contents(stat_buf.st_size);
    // NB: Reading one extra byte should mean we get an EOF and only size bytes.
    //     Also, since we know it's a true file, we don't need to worry about
    //     short counts and EINTR.
    unsigned recd = fread(file_contents.data(), sizeof(char), stat_buf.st_size + 1, storage_file);
    if (recd != file_contents.size() || !feof(storage_file))
      return {true, "Incorrect number of bytes read from: " + filename, {}};


    vector<uint8_t>::const_iterator iterator = file_contents.begin();
    while(iterator <= file_contents.end()){
      /// - 8-byte constant AUTHAUTH or KVKVKVKV
      string identifier = string(iterator, iterator + 8);
      iterator += 8;
      if (identifier == AUTHENTRY){
        AuthTableEntry entry;
        vector<uint8_t> uname;
        /// - 8-byte binary write of the length of the username
        /// - Binary write of the bytes of the username
        getLenThenReadToVec(iterator, uname, LEN_UNAME);
        entry.username = string(uname.begin(), uname.end());
        /// - 8-byte binary write of the length of the salt
        /// - Binary write of the bytes of the salt
        getLenThenReadToVec(iterator, entry.salt, LEN_SALT);
        /// - 8-byte binary write of the length of the hashed password
        /// - Binary write of the bytes of the hashed password
        getLenThenReadToVec(iterator, entry.pass_hash, LEN_PASSHASH);
        /// - 8-byte binary write of the length of the profile file
        /// - Binary write of the bytes of the profile file
        getLenThenReadToVec(iterator, entry.content, LEN_PROFILE_FILE);
        while (*iterator != 'A' && *iterator != 'K'){
          iterator++;
        }
        auto onsuccess = [](){};
        if(!auth_table->insert(string(uname.begin(), uname.end()), entry, onsuccess)){
          return {false, RES_ERR_USER_EXISTS, {}};
        }
      }
      // if its KVKVKVKV then read a KV store entry
      else if (identifier == KVENTRY){
        string key;
        vector<uint8_t> val;
        vector<uint8_t> key_vec;
        /// - 8-byte binary write of the length of the key
        /// - Binary write of the bytes of the username
        getLenThenReadToVec(iterator, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());
        /// - 8-byte binary write of the length of the value
        /// - Binary write of the bytes of the value
        getLenThenReadToVec(iterator, val, LEN_VAL);
        /// Iterate through padding bytes until the next entry
        while (*iterator != 'A' && *iterator != 'K'){
          iterator++;
        }

        auto onsuccess = [](){};
        if(!kv_store->insert(key, val, onsuccess)){
          return {false, RES_ERR_USER_EXISTS, {}};
        }
      }
      else if (identifier == AUTHDIFF){
        vector<uint8_t> uname;
        vector<uint8_t> profile_file;
        /// - 8-byte binary write of the length of the username
        /// - Binary write of the bytes of the username
        getLenThenReadToVec(iterator, uname, LEN_UNAME);
        /// - 8-byte binary write of the length of the profile file
        /// - Binary write of the bytes of the profile file
        getLenThenReadToVec(iterator, profile_file, LEN_PROFILE_FILE);
        while (*iterator != 'A' && *iterator != 'K'){
          iterator++;
        }
        auto set_content = [&](AuthTableEntry &a){ 
          a.content = profile_file;
        };
        if(!auth_table->do_with(string(uname.begin(), uname.end()), set_content)){
          return {false, RES_ERR_SERVER, {}};
        }
      }
      else if (identifier == KVUPDATE){
        string key;
        vector<uint8_t> val;
        vector<uint8_t> key_vec;
        /// - 8-byte binary write of the length of the key
        /// - Binary write of the bytes of the username
        getLenThenReadToVec(iterator, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());
        /// - 8-byte binary write of the length of the value
        /// - Binary write of the bytes of the value
        getLenThenReadToVec(iterator, val, LEN_VAL);
        /// Iterate through padding bytes until the next entry
        while (*iterator != 'A' && *iterator != 'K'){
          iterator++;
        }

        auto onsuccess = [](){};
        if(kv_store->upsert(key, val, onsuccess, onsuccess)){
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else if (identifier == KVDELETE){
        string key;
        vector<uint8_t> key_vec;
        /// - 8-byte binary write of the length of the key
        /// - Binary write of the bytes of the username
        getLenThenReadToVec(iterator, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());
        /// Iterate through padding bytes until the next entry
        while (*iterator != 'A' && *iterator != 'K'){
          iterator++;
        }

        auto onsuccess = [](){};
        if(!kv_store->remove(key, onsuccess)){
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        return{false, RES_ERR_SERVER, {}};
      }

    }

    return {true, "Loaded: " + filename, {}};
  }
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
