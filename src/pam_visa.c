#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <syslog.h>
#include "lib/validation.h"


PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv) {
    const char * public_key_file = NULL;
    int  expiration_in_seconds = -1;

    if (argc > 0)  {
        public_key_file = argv[0];
        syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: public_key_file = %s", public_key_file);
    }

    if (argc > 1) {
        expiration_in_seconds = atoi(argv[1]);
        syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: expiration_in_seconds = %d", expiration_in_seconds);
    }

    if (public_key_file == NULL || *public_key_file == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Public key file path is not defined");
        return PAM_AUTHINFO_UNAVAIL;
    }

    const char *user = NULL;
    const char *password = NULL;

    // Get the user
    int pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL){
        return PAM_IGNORE;
    }

    // Get the password (token)
    int ret_val = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (ret_val != PAM_SUCCESS || password == NULL) {
        return PAM_IGNORE;
    }

    // Validate user against the token
    if (visa_verify_body_and_signature(public_key_file, expiration_in_seconds, user, password)) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_visa: Body and signature verified");
        return PAM_SUCCESS;
    }

    return PAM_IGNORE;
}
