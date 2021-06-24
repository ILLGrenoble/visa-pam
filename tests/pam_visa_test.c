#include <stdlib.h>
#include <stdint.h>
#include <check.h>
#include <stdio.h>
#include "lib/validation.h"

START_TEST(test_valid_signature){
  int result = visa_verify_body_and_signature("../tests/resources/public.pem",
                                 -1,
                                 "hall",
                                 "hall,1624520361;hgpWa8aUamXRZnaKlUr6Y8pgnM+f9+ms9kAfkZXSezva2u02o/+OMlqfqa/Mqk+pD+ZldfaftTsDFwMW3K/65w==");
  ck_assert_int_eq(1, result);
}
END_TEST

START_TEST(test_signature_has_expired){
  int result = visa_verify_body_and_signature("../tests/resources/public.pem",
                                 10,
                                 "hall",
                                 "hall,1624520361;hgpWa8aUamXRZnaKlUr6Y8pgnM+f9+ms9kAfkZXSezva2u02o/+OMlqfqa/Mqk+pD+ZldfaftTsDFwMW3K/65w==");
  ck_assert_int_eq(0, result);
}
END_TEST

START_TEST(test_invalid_signature){
  int result = visa_verify_body_and_signature("../tests/resources/public.pem", 
                                  -1,
                                 "hall",
                                 "hall,1624520361;hgpWa8aUamXyJKXRZnaKlUr6Y8pgnM+f9+ms9kAfkZXSezva2u02o/+OMlqfqa/Mqk+pD+ZldfaftTsDFwMW3K/65w==");
  ck_assert_int_eq(0, result);
}
END_TEST

START_TEST(test_signature_username_does_not_match_given_username){
 int result = visa_verify_body_and_signature("../tests/resources/public.pem",
                                 -1,
                                 "hall",
                                 "bloggs,1624521156;MQD6abCjE4Yot9eBfLba9l4nq2/VazcQ924Hf8lUxn8PC4DgO89jO9D8X1jbqse3WL8FZ5AQjTjwLBbGNSUIJQ==");
  ck_assert_int_eq(0, result);
}
END_TEST

START_TEST(test_given_username_does_not_match_signature_username){
  int result = visa_verify_body_and_signature("../tests/resources/public.pem",
                                 -1,
                                 "bloggs",
                                 "hall,1624520361;hgpWa8aUamXRZnaKlUr6Y8pgnM+f9+ms9kAfkZXSezva2u02o/+OMlqfqa/Mqk+pD+ZldfaftTsDFwMW3K/65w==");
  ck_assert_int_eq(0, result);
}
END_TEST

START_TEST(test_empty_signature){
  int result = visa_verify_body_and_signature("../tests/resources/public.pem", 15, "hall", "");
  ck_assert_int_eq(0, result);
}
END_TEST

Suite * make_test_suite(void) {
  Suite *suite = suite_create("Core");
  TCase *core = tcase_create("Core");
 
  tcase_add_test(core, test_valid_signature);
  tcase_add_test(core, test_invalid_signature);
  tcase_add_test(core, test_empty_signature);
  tcase_add_test(core, test_signature_username_does_not_match_given_username);
  tcase_add_test(core, test_given_username_does_not_match_signature_username);
  tcase_add_test(core, test_signature_has_expired);

  suite_add_tcase(suite, core);

  return suite;
}

int main(void) {

  SRunner *runner = srunner_create(make_test_suite());
  srunner_run_all(runner, CK_VERBOSE);

  int number_failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  
  if(number_failed == 0) {
    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;

}