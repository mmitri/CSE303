#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

#include "err.h"

using namespace std;

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt (start)
/// @param count Number of bytes of the message
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start, int count) {
 const int AES_BLOCKSIZE = 1024;
 // the vector of bytes that are encrypted
 vector<uint8_t> encryptedMsg;
 
 // Get the size of the AES block
 int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
 
 // A buffer to place the crypted bits into.
 unsigned char out_buf[AES_BLOCKSIZE + cipher_block_size];
 
 // Extra bytes at the end of an AES encryption that it has to treat special
 int out_len;
 
 int num_bytes_read = 0;
 
 while(true){
   unsigned char in_buf[AES_BLOCKSIZE];
   memcpy(in_buf, &start[num_bytes_read], AES_BLOCKSIZE);
   num_bytes_read += AES_BLOCKSIZE;

   int num_bytes_to_crypt = (num_bytes_read > count ? count - num_bytes_read + AES_BLOCKSIZE : AES_BLOCKSIZE);

   // crypting message (encrypt or decrypt depending on the format of ctx)
   if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_to_crypt)){
     fprintf(stderr, "Error in EVP_CipherUpdate: %s\n", ERR_error_string(ERR_get_error(), nullptr));
     return {};
   }
   // Add buffer bytes to vector
   encryptedMsg.insert(encryptedMsg.end(), &out_buf[0], &out_buf[out_len]);
 
   if (num_bytes_read > count){
     break;
   }
 }

 // If there is an extra bit of bytes
 if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
   fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
           ERR_error_string(ERR_get_error(), nullptr));
   return {};
 }
 // Add buffer bytes to vector
 encryptedMsg.insert(encryptedMsg.end(), &out_buf[0], &out_buf[out_len]);
 return encryptedMsg;
}

