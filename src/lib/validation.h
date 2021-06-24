#ifndef PAM_VISA_VALIDATION_H
#define PAM_VISA_VALIDATION_H

#include <stdlib.h>
#include <time.h>

int visa_rsa_verify_signature(const char * public_key_filename, unsigned char * message_hash, size_t message_hash_length, const char * message, size_t message_length);

int visa_verify_signature(const char * public_key_filename, const char * message, size_t message_length, const char * signature_base64);

size_t visa_calc_decode_length(const char * b64_input);

void visa_base64_decode(const char * b64_message, unsigned char ** decoded_message, size_t * decoded_message_length);

int visa_delim_count(const char * text, size_t text_length, char delim, size_t * last_delim_position);

int visa_verify_body_and_signature(const char * public_key_filename, int expiration_in_seconds, const char * user, const char * body);

int visa_verify_username_matches_signature(char * user, char * signature_user);

int visa_verify_timestamp_has_not_expired(time_t timestamp, const int expiration);


#endif /* PAM_VISA_VALIDATION_H */
