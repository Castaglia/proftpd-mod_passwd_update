/*
 * ProFTPD - mod_passwd_update API testsuite
 * Copyright (c) 2021-2022 TJ Saunders <tj@castaglia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

/* Password tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.passwd", 1, 20);
  }

  mark_point();
  passwd_update_init_salt();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.passwd", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (passwd_get_hash_test) {
  const char *hash, *plaintext;

  mark_point();
  hash = passwd_update_get_hash(NULL, NULL, 0);
  ck_assert_msg(hash == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  hash = passwd_update_get_hash(p, NULL, 0);
  ck_assert_msg(hash == NULL, "Failed to handle null plaintext");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  plaintext = "password";

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, 0);
  ck_assert_msg(hash == NULL, "Failed to handle unknown algorithm ID");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, PASSWD_UPDATE_ALGO_SHA256);
  ck_assert_msg(hash != NULL, "Failed to get SHA256 password hash: %s",
    strerror(errno));

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, PASSWD_UPDATE_ALGO_SHA512);
  ck_assert_msg(hash != NULL, "Failed to get SHA512 password hash: %s",
    strerror(errno));
}
END_TEST

START_TEST (passwd_from_text_test) {
  struct passwd *pwd;
  const char *text;
  size_t text_len;

  mark_point();
  pwd = passwd_update_from_text(NULL, NULL, 0);
  ck_assert_msg(pwd == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  pwd = passwd_update_from_text(p, NULL, 0);
  ck_assert_msg(pwd == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "foobar";

  mark_point();
  pwd = passwd_update_from_text(p, text, 0);
  ck_assert_msg(pwd == NULL, "Failed to handle zero textlen");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text_len = strlen(text);

  mark_point();
  pwd = passwd_update_from_text(p, text, text_len);
  ck_assert_msg(pwd == NULL, "Failed to handle invalid text");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  /* XXX TODO:
   *  fill in tests
   */

  text = "test:enterpasswordhashhere:1:1::/home/test:/bin/bash";
  text_len = strlen(text);

  mark_point();
  pwd = passwd_update_from_text(p, text, text_len);
  ck_assert_msg(pwd != NULL, "Failed to handle valid text: %s", strerror(errno));
  ck_assert_msg(strcmp(pwd->pw_name, "test") == 0,
    "Expected pw_name 'test', got '%s'", pwd->pw_name);
  ck_assert_msg(strcmp(pwd->pw_passwd, "enterpasswordhashhere") == 0,
    "Expected pw_passwd 'enterpasswordhashhere', got '%s'",
    pwd->pw_passwd);
  ck_assert_msg(pwd->pw_uid == (uid_t) 1, "Expected pw_uid 1, got %lu",
    (unsigned long) pwd->pw_uid);
  ck_assert_msg(pwd->pw_gid == (gid_t) 1, "Expected pw_gid 1, got %lu",
    (unsigned long) pwd->pw_gid);
  ck_assert_msg(strcmp(pwd->pw_gecos, "") == 0,
    "Expected pw_gecos '', got '%s'", pwd->pw_gecos);
  ck_assert_msg(strcmp(pwd->pw_dir, "/home/test") == 0,
    "Expected pw_dir '/home/test', got '%s'", pwd->pw_dir);
  ck_assert_msg(strcmp(pwd->pw_shell, "/bin/bash") == 0,
    "Expected pw_shell '/bin/bash', got '%s'", pwd->pw_shell);
}
END_TEST

START_TEST (passwd_to_text_test) {
  const char *text, *expected;
  struct passwd pwd;

  mark_point();
  text = passwd_update_to_text(NULL, NULL);
  ck_assert_msg(text == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = passwd_update_to_text(p, NULL);
  ck_assert_msg(text == NULL, "Failed to handle null passwd");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&pwd, 0, sizeof(pwd));

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  ck_assert_msg(text == NULL, "Failed to handle null pw_name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pwd.pw_name = "test";

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  ck_assert_msg(text == NULL, "Failed to handle null pw_passwd");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* All other fields are largely optional. */

  pwd.pw_passwd = "enterpasswordhashhere";
  pwd.pw_uid = 1;
  pwd.pw_gid = 1;
  pwd.pw_dir = "/home/test";
  pwd.pw_shell = "/bin/bash";

  expected = "test:enterpasswordhashhere:1:1::/home/test:/bin/bash";

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  ck_assert_msg(text != NULL, "Failed to handle pwd: %s", strerror(errno));
  ck_assert_msg(strcmp(text, expected) == 0, "Expected '%s', got '%s'",
    expected, text);
}
END_TEST

Suite *tests_get_passwd_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("passwd");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, passwd_get_hash_test);
  tcase_add_test(testcase, passwd_from_text_test);
  tcase_add_test(testcase, passwd_to_text_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
