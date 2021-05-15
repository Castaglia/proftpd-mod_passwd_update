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

extern xaset_t *server_list;

int passwd_update_logfd = -1;
module passwd_update_module;
pool *passwd_update_pool = NULL;

static int passwd_update_engine = FALSE;

static const char *trace_channel = "passwd_update";

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
  config_rec *c;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "missing required parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* XXX TODO:
   *   Currently implemented: sha512, sha256
   *
   * Default: PasswordUpdateAlgorithms sha512 sha256
   *
   * NO DES support, or MD5?
   */
  for (i = 1; i < cmd->argc; i++) {
    int algo_id;

    if (strcasecmp(cmd->argv[i], "sha256") == 0 ||
        strcasecmp(cmd->argv[i], "sha2-256") == 0) {
      algo_id = PASSWD_UPDATE_ALGO_SHA256;

    } else if (strcasecmp(cmd->argv[i], "sha512") == 0 ||
               strcasecmp(cmd->argv[i], "sha2-512") == 0) {
      algo_id = PASSWD_UPDATE_ALGO_SHA512;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unknown/unsupported PasswordUpdateAlgorithm requested: ",
        cmd->argv[i], NULL));
    }
  }

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
  if (passwd_update_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

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
  register unsigned int i;
  config_rec *c;
  server_rec *s;

  /* XXX TODO:
   *   Iterate through list of vhosts
   *     if PasswordUpdateEngine enabled
   *       check list of configured vhost PasswordUpdateAlgorithms
   *         verify that `crypt(3)` supports that algo
   */
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
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "PasswordUpdateEngine", FALSE);
  if (c != NULL) {
    passwd_update_engine = *((int *) c->argv[0]);
  }

  if (passwd_update_engine == FALSE) {
    return 0;
  }

  (void) passwd_update_openlog();
  return 0;
}

/* Module API tables
 */

static conftable passwd_update_conftab[] = {
  { "PasswordUpdateAlgorithms",	set_passwdupdatealgos,		NULL },
  { "PasswordUpdateEngine",	set_passwdupdateengine,		NULL },
  { "PasswordUpdateLog",	set_passwdupdatelog,		NULL },

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
