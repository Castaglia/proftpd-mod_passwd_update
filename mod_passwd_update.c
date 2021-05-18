/*
 * ProFTPD - mod_passwd_update
 * Copyright (c) 2021 TJ Saunders
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_passwd_update.a $
 */

#include "mod_passwd_update.h"
#include "passwd.h"
#include "file.h"

extern xaset_t *server_list;

int passwd_update_logfd = -1;
module passwd_update_module;
pool *passwd_update_pool = NULL;

static int passwd_update_engine = FALSE;

static const char *passwd_update_old_auth_user_file = NULL;
static const char *passwd_update_new_auth_user_file = NULL;

static const char *trace_channel = "passwd_update";

static const char *get_algo_name(unsigned int algo_id) {
  const char *text;

  switch (algo_id) {
    case PASSWD_UPDATE_ALGO_SHA256:
      text = "SHA256";
      break;

    case PASSWD_UPDATE_ALGO_SHA512:
      text = "SHA512";
      break;

    default:
      text = "(unknown/unsupported)";
      break;
  }

  return text;
}

static int passwd_update_openlog(void) {
  int res = 0;
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "PasswordUpdateLog", FALSE);
  if (c != NULL) {
    const char *logfile;

    logfile = c->argv[0];
    if (strcasecmp(logfile, "none") != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(logfile, &passwd_update_logfd, 0600);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PASSWD_UPDATE_VERSION
            ": notice: unable to open PasswordUpdateLog '%s': %s", logfile,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_PASSWD_UPDATE_VERSION
            ": notice: unable to open PasswordUpdateLog '%s': parent "
            "directory is world-writable", logfile);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_PASSWD_UPDATE_VERSION
            ": notice: unable to open PasswordUpdateLog '%s': cannot log "
            "to a symlink", logfile);
        }
      }
    }
  }

  return res;
}

/* Configuration handlers
 */

/* usage: PasswordUpdateAlgorithms algo1 ... */
MODRET set_passwdupdatealgos(cmd_rec *cmd) {
  register unsigned int i;
  unsigned int algo_count, *algos;
  config_rec *c;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "missing required parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[1] = palloc(c->pool, sizeof(unsigned int));

  algo_count = cmd->argc-1;
  algos = pcalloc(c->pool, sizeof(unsigned int) * algo_count);

  for (i = 1; i < cmd->argc; i++) {
    unsigned int algo_id;

    if (strcasecmp(cmd->argv[i], "sha256") == 0 ||
        strcasecmp(cmd->argv[i], "sha2-256") == 0) {
      algo_id = PASSWD_UPDATE_ALGO_SHA256;

    } else if (strcasecmp(cmd->argv[i], "sha512") == 0 ||
               strcasecmp(cmd->argv[i], "sha2-512") == 0) {
      algo_id = PASSWD_UPDATE_ALGO_SHA512;

    } else if (strcasecmp(cmd->argv[i], "des") == 0) {
      algo_id = PASSWD_UPDATE_ALGO_DES;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unknown/unsupported PasswordUpdateAlgorithm requested: ",
        cmd->argv[i], NULL));
    }

    algos[i-1] = algo_id;
  }

  c->argv[0] = algos;
  *((unsigned int *) c->argv[1]) = algo_count;

  return PR_HANDLED(cmd);
}

/* usage: PasswordUpdateAuthUserFiles old-path new-path */
MODRET set_passwdupdateaauthuserfiles(cmd_rec *cmd) {
  config_rec *c;
  char *old_path, *new_path;
  int fd, xerrno;

  if (cmd->argc != 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  old_path = cmd->argv[1];
  if (*old_path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unable to use relative path for ", (char *) cmd->argv[0], " '",
      old_path, "'", NULL));
  }

  new_path = cmd->argv[2];
  if (*new_path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unable to use relative path for ", (char *) cmd->argv[0], " '",
      new_path, "'", NULL));
  }

  /* Make sure the new path exists. */
  PRIVS_ROOT
  fd = open(new_path, O_RDWR|O_CREAT, 0600);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fd < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "error opening '%s': %s", new_path, strerror(xerrno), NULL));
  }

  (void) close(fd);

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, old_path);
  c->argv[1] = pstrdup(c->pool, new_path);

  return PR_HANDLED(cmd);
}

/* usage: PasswordUpdateEngine on|off */
MODRET set_passwdupdateengine(cmd_rec *cmd) {
  int engine = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: PasswordUpdateLog path|"none" */
MODRET set_passwdupdatelog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET passwd_update_pre_pass(cmd_rec *cmd) {
  register unsigned int i;
  const char *user, *text, *proto;
  unsigned char *authenticated;
  config_rec *c;
  pr_fh_t *fh;
  int flags, res, xerrno;
  struct passwd *pwd;
  unsigned int algo_count, *algos;

  if (passwd_update_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* We currently only work for FTP, not SFTP. */
  proto = pr_session_get_protocol(0);
  if (strcmp(proto, "ftp") != 0 &&
      strcmp(proto, "ftps") != 0) {
    char *sftp_auth_method;

    /* Check for the SFTP_USER_AUTH_METHOD environment variable, set by
     * mod_sftp.  If it is not present, then mod_sftp is too old -- and we
     * MUST use this environment variable, to know when password-based SSH
     * sessions (vs publickey auth sessions) are used.
     */
    sftp_auth_method = pr_env_get(cmd->tmp_pool, "SFTP_USER_AUTH_METHOD");
    if (sftp_auth_method == NULL) {
      pr_trace_msg(trace_channel, 9,
        "skipping password migration for %s protocol session", proto);
      return PR_DECLINED(cmd);
    }

    if (strcmp(sftp_auth_method, "password") != 0) {
      pr_trace_msg(trace_channel, 9,
        "skipping password migration for %s protocol session with %s "
        "authentication", proto, sftp_auth_method);
      return PR_DECLINED(cmd);
    }
  }

  /* Handle cases where the client already authenticated. */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated != NULL &&
      *authenticated == TRUE) {
    pr_trace_msg(trace_channel, 9,
      "client already authenticated, ignoring PASS command");
    return PR_DECLINED(cmd);
  }

  /* Handle cases where PASS might be sent before USER. */
  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    pr_trace_msg(trace_channel, 9,
      "client has not sent USER command, ignoring PASS command");
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "AllowEmptyPasswords",
    FALSE);
  if (c != NULL) {
    int allow_empty_passwords;

    allow_empty_passwords = *((int *) c->argv[0]);
    if (allow_empty_passwords == FALSE) {
      size_t passwd_len = 0;

      if (cmd->argc > 1 &&
          cmd->arg != NULL) {
        passwd_len = strlen(cmd->arg);
      }

      if (passwd_len == 0) {
        /* Let other modules deal with this. */
        pr_trace_msg(trace_channel, 9,
          "client sent empty password, ignoring PASS command");
        return PR_DECLINED(cmd);
      }
    }
  }

  PRIVS_ROOT
  fh = pr_fsio_open(passwd_update_new_auth_user_file, O_RDONLY);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error opening '%s': %s", passwd_update_new_auth_user_file,
      strerror(xerrno));
    return PR_DECLINED(cmd);
  }

  flags = PASSWD_UPDATE_FILE_FL_USE_LOCK;
  pwd = passwd_update_file_get_entry(cmd->tmp_pool, fh, user, flags);
  (void) pr_fsio_close(fh);

  if (pwd != NULL) {
    pr_trace_msg(trace_channel, 9,
      "found existing entry for user '%s' in '%s'", user,
      passwd_update_new_auth_user_file);
    return PR_DECLINED(cmd);
  }

  PRIVS_ROOT
  fh = pr_fsio_open(passwd_update_old_auth_user_file, O_RDONLY);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error opening '%s': %s", passwd_update_old_auth_user_file,
      strerror(xerrno));
    return PR_DECLINED(cmd);
  }

  flags = 0;
  pwd = passwd_update_file_get_entry(cmd->tmp_pool, fh, user, flags);
  (void) pr_fsio_close(fh);

  if (pwd == NULL) {
    pr_trace_msg(trace_channel, 9,
      "no entry found for user '%s' in '%s'", user,
      passwd_update_old_auth_user_file);
    return PR_DECLINED(cmd);
  }

  /* Verify that the given password matches this entry. */
  text = crypt(cmd->arg, pwd->pw_passwd);
  xerrno = errno;

  if (text == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error using crypt(3) for user '%s': %s", user, strerror(xerrno));
    return PR_DECLINED(cmd);
  }

  if (strcmp(text, pwd->pw_passwd) != 0) {
    /* Wrong password */
    pr_trace_msg(trace_channel, 9, "wrong password for user '%s', ignoring",
      user);
    return PR_DECLINED(cmd);
  }

  /* At this point, we have the entry for the known user from the old
   * AuthUserFile; we can now update the password hash and add the
   * updated entry to the new AuthUserFile.
   */

  c = find_config(main_server->conf, CONF_PARAM, "PasswordUpdateAlgorithms",
    FALSE);
  if (c != NULL) {
    algos = c->argv[0];
    algo_count = *((unsigned int *) c->argv[1]);

  } else {
    algo_count = 2;
    algos = palloc(cmd->tmp_pool, sizeof(unsigned int) * algo_count);
    algos[0] = PASSWD_UPDATE_ALGO_SHA512;
    algos[1] = PASSWD_UPDATE_ALGO_SHA256;
  }

  for (i = 0; i < algo_count; i++) {
    unsigned int algo_id;

    algo_id = algos[i];
    text = passwd_update_get_hash(cmd->tmp_pool, cmd->arg, algo_id);
    if (text != NULL) {
      break;
    }
  }

  if (text == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "unable to generate updated password hash: %s", strerror(errno));
    return PR_DECLINED(cmd);
  }

  pwd->pw_passwd = (char *) text;

  PRIVS_ROOT
  fh = pr_fsio_open(passwd_update_new_auth_user_file, O_WRONLY);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error opening '%s': %s", passwd_update_new_auth_user_file,
      strerror(xerrno));
    return PR_DECLINED(cmd);
  }

  res = passwd_update_file_add_entry(cmd->tmp_pool, fh, pwd);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error adding updated user '%s' entry to '%s': %s", user,
      passwd_update_new_auth_user_file, strerror(xerrno));
  }

  if (pr_fsio_close(fh) < 0) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "error writing '%s': %s", passwd_update_new_auth_user_file,
      strerror(xerrno));
  }

  (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
    "successfully updated password hash for user '%s'", user);
  return PR_DECLINED(cmd);
}

/* Event listeners
 */

#if defined(PR_SHARED_MODULE)
static void passwd_update_mod_unload_ev(const void *event_data,
    void *user_data) {
  register unsigned int i;

  if (strcmp((const char *) event_data, "mod_passwd_update.c") != 0) {
    return;
  }

  /* Unregister ourselves from all events. */
  pr_event_unregister(&passwd_update_module, NULL, NULL);

  destroy_pool(passwd_update_pool);
  passwd_update_pool = NULL;

  (void) close(passwd_update_logfd);
  passwd_update_logfd = -1;
}
#endif /* PR_SHARED_MODULE */

static void passwd_update_postparse_ev(const void *event_data,
    void *user_data) {
  server_rec *s;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(passwd_update_pool);

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;
    int engine;

    pr_signals_handle();

    c = find_config(s->conf, CONF_PARAM, "PasswordUpdateEngine", FALSE);
    if (c == NULL) {
      continue;
    }

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      continue;
    }

    c = find_config(s->conf, CONF_PARAM, "PasswordUpdateAlgorithms", FALSE);
    if (c != NULL) {
      register unsigned int i;
      unsigned int algo_count, *algos;

      algos = c->argv[0];
      algo_count = *((unsigned int *) c->argv[1]);

      for (i = 0; i < algo_count; i++) {
        unsigned int algo_id;
        const char *text;

        algo_id = algos[i];
        text = passwd_update_get_hash(tmp_pool, "test", algo_id);
        if (text == NULL) {
          pr_trace_msg(trace_channel, 3, "error getting updated %s hash: %s",
            get_algo_name(algo_id), strerror(errno));
          pr_log_pri(PR_LOG_NOTICE, MOD_PASSWD_UPDATE_VERSION
            ": crypt(3) does not support %s algorithm", get_algo_name(algo_id));
        }
      }
    }
  }

  destroy_pool(tmp_pool);
}

/* Initialization routines
 */

static int passwd_update_init(void) {
  passwd_update_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(passwd_update_pool, MOD_PASSWD_UPDATE_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&passwd_update_module, "core.module-unload",
    passwd_update_mod_unload_ev, NULL);
#endif
  pr_event_register(&passwd_update_module, "core.postparse",
    passwd_update_postparse_ev, NULL);

  return 0;
}

static int passwd_update_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "PasswordUpdateEngine", FALSE);
  if (c != NULL) {
    passwd_update_engine = *((int *) c->argv[0]);
  }

  if (passwd_update_engine == FALSE) {
    return 0;
  }

  (void) passwd_update_openlog();

  c = find_config(main_server->conf, CONF_PARAM, "PasswordUpdateAuthUserFiles",
    FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(passwd_update_logfd, MOD_PASSWD_UPDATE_VERSION,
      "missing required PasswordUpdateAuthUserFiles directive");
    passwd_update_engine = FALSE;
    return 0;
  }

  passwd_update_old_auth_user_file = c->argv[0];
  passwd_update_new_auth_user_file = c->argv[1];
  return 0;
}

/* Module API tables
 */

static conftable passwd_update_conftab[] = {
  { "PasswordUpdateAlgorithms",		set_passwdupdatealgos,		NULL },
  { "PasswordUpdateAuthUserFiles",	set_passwdupdateaauthuserfiles,	NULL },
  { "PasswordUpdateEngine",		set_passwdupdateengine,		NULL },
  { "PasswordUpdateLog",		set_passwdupdatelog,		NULL },

  { NULL }
};

static cmdtable passwd_update_cmdtab[] = {
  { PRE_CMD,		C_PASS,	G_NONE,	passwd_update_pre_pass,	FALSE, FALSE },

  { 0, NULL }
};

module passwd_update_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "passwd_update",

  /* Module configuration handler table */
  passwd_update_conftab,

  /* Module command handler table */
  passwd_update_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  passwd_update_init,

  /* Session initialization */
  passwd_update_sess_init,

  /* Module version */
  MOD_PASSWD_UPDATE_VERSION
};
