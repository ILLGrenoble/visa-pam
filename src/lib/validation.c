#include <string.h>
#include <syslog.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <time.h>

int visa_rsa_verify_signature(const char * public_key_filename, unsigned char * message_hash, size_t message_hash_length, const char * message, size_t message_length) {
  FILE * public_key_file = fopen(public_key_filename, "rt");

  if (!public_key_file) {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Failed to read public key");
    return 0;
  }

  EVP_PKEY * public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);

  if (!public_key) {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Failed to decrypt the public key");
    return 0;
  }

  EVP_MD_CTX * rsa_context = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(rsa_context, NULL, EVP_sha256(), NULL, public_key) <= 0) {
    return 0;
  }

  if (EVP_DigestVerifyUpdate(rsa_context, message, message_length) <= 0) {
    return 0;
  }

  int result = EVP_DigestVerifyFinal(rsa_context, message_hash, message_hash_length);

  EVP_MD_CTX_destroy(rsa_context);

  return result;
}

size_t visa_calc_decode_length(const char * b64_input) {
  size_t len = strlen(b64_input), padding = 0;

  if (b64_input[len - 1] == '=' && b64_input[len - 2] == '=') {
    padding = 2;
  } else if (b64_input[len - 1] == '=') {
    padding = 1;
  }
  return (len * 3) / 4 - padding;
}

void visa_base64_decode(const char * b64_message, unsigned char ** decoded_message, size_t * decoded_message_length) {
  BIO *bio, *b64;

  int decode_length = visa_calc_decode_length(b64_message);
  *decoded_message = (unsigned char*) malloc(decode_length + 1);
  (*decoded_message)[decode_length] = '\0';

  bio = BIO_new_mem_buf(b64_message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer

  *decoded_message_length = BIO_read(bio, *decoded_message, strlen(b64_message));
  BIO_free_all(bio);
}

int visa_verify_signature(const char * public_key_filename, const char * message, size_t message_length, const char * signature_base64) {
  unsigned char* decoded_signature;
  size_t decoded_signature_length;

  visa_base64_decode(signature_base64, &decoded_signature, &decoded_signature_length);

  int retval = visa_rsa_verify_signature(public_key_filename, decoded_signature, decoded_signature_length, message, message_length);

  if (retval == 1) {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Signature is valid");
  } else {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Signature is invalid");
  }

  free(decoded_signature);

  return retval;
}

int visa_delim_count(const char * text, size_t text_length, char delim, size_t * last_delim_position)  { 
    // Count variable 
    int result = 0; 
    for (int i = 0; i < text_length; i++) {
        if (text[i] == delim) {
            *last_delim_position = i;
            result++; 
        }
    }

    return result; 
}

int visa_verify_username_matches_signature(const char * user, const char * signature_user) {
  if (strncmp(signature_user, user, strlen(user)) == 0) {
      return 1;
  };
  return 0;
}

int visa_verify_timestamp_has_not_expired(time_t timestamp, long expiration) {
  if (expiration == -1) {
    return 1;
  }
  time_t now = time(NULL);
  time_t delta =  difftime(now, timestamp);
  if (delta > expiration) {
    return 0;
  }
  return 1;
}

int visa_verify_body_and_signature(const char * public_key_filename, int expiration_in_seconds, const char * user, const char * body) {

  // Verify we have two parts
  size_t delim_position;
  if (visa_delim_count(body, strlen(body), ';', &delim_position) != 1) {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Body structure is invalid");
    return 0;
  }

  size_t message_length = delim_position;

  // Pointer to signature
  const char * signature_base64 = body + delim_position + 1;

  // Verify we have two parts to the message
  if (visa_delim_count(body, message_length, ',', &delim_position) != 1) {
    syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Message structure is invalid");
    return 0;
  }

  // Verify username matches message
  if(visa_verify_username_matches_signature(user, body) != 1) {
      syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Username is invalid");
      return 0;
  }

  // Get the timestamp in a long format
  size_t timestamp_length = message_length - delim_position - 1;
  char * timestamp_string = malloc(timestamp_length + 1);
  strncpy(timestamp_string, body + delim_position + 1, timestamp_length);
  timestamp_string[timestamp_length] = '\0';
  time_t timestamp = atol(timestamp_string);

  if(visa_verify_timestamp_has_not_expired(timestamp, expiration_in_seconds) != 1) {
      syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Signature has expired");
      return 0;
  }

  free(timestamp_string);

  return visa_verify_signature(public_key_filename, body, message_length, signature_base64);
}

