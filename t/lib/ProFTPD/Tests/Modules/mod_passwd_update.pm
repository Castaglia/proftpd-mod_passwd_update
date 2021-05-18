package ProFTPD::Tests::Modules::mod_passwd_update;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use Cwd;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  passwd_update_unknown_user => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  passwd_update_bad_password => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  passwd_update_algo_sha256 => {
    order => ++$order,
    test_class => [qw(forking os_linux)],
  },

  passwd_update_algo_sha512 => {
    order => ++$order,
    test_class => [qw(forking os_linux)],
  },

  passwd_update_algo_des => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  passwd_update_authorder_without_auth_file => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  passwd_update_sftp_ignore_publickey_auth => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  passwd_update_sftp_handle_password_auth => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },
};

sub new {
  return shift()->SUPER::new(@_);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/ssh_host_rsa_key');
  unless (chmod(0400, $rsa_host_key)) {
    die("Can't set perms on $rsa_host_key: $!");
  }
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSH2
  #  Net-SSH2-SFTP

  my $required = [qw(
    Net::SSH2
    Net::SSH2::SFTP
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub passwd_update_unknown_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login('unknown_user', $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /no entry found for user 'unknown_user'/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'no entry found' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_bad_password {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, 'badpasswd') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /wrong password for user/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'wrong password' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_algo_sha256 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  # Mac's crypt(3) doesn't support SHA256.  Sigh.
  if ($^O eq 'darwin') {
    print STDERR " + Skipping SHA256 test due to lack of support on Mac\n";
    return;
  }

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
        PasswordUpdateAlgorithms => 'SHA256',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      # Log in again, make sure we can use the newly written entry.
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /generated SHA256 salt/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'SHA256 salt' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_algo_sha512 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  # Mac's crypt(3) doesn't support SHA512.  Sigh.
  if ($^O eq 'darwin') {
    print STDERR " + Skipping SHA512 test due to lack of support on Mac\n";
    return;
  }

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
        PasswordUpdateAlgorithms => 'SHA512',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      # Log in again, make sure we can use the newly written entry.
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /generated SHA512 salt/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'SHA512 salt' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_algo_des {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
        PasswordUpdateAlgorithms => 'DES',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      # Log in again, make sure we can use the newly written entry.
      $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 5);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /generated DES salt/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'DES salt' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_authorder_without_auth_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $algos = 'sha512 sha256';
  if ($^O eq 'darwin') {
    # Mac's crypt(3) doesn't support SHA256/SHA512.  Sigh.
    $algos = 'des';
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthOrder => 'mod_auth_unix.c',
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
        PasswordUpdateAlgorithms => $algos,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /not found in AuthOrder, skipping password migration/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'no entry found' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_sftp_ignore_publickey_auth {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/test_rsa_key.pub');
  my $rsa_rfc4716_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/authorized_rsa_keys');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
      },

      'mod_sftp.c' => {
        SFTPEngine => 'on',
        SFTPLog => $setup->{log_file},
        SFTPHostKey => $rsa_host_key,
        SFTPAuthorizedUserKeys => 'file:~/.authorized_keys',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /skipping password migration for ssh2 protocol session with publickey authentication/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'no entry found' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub passwd_update_sftp_handle_password_auth {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  my $algos = 'sha512 sha256';
  if ($^O eq 'darwin') {
    # Mac's crypt(3) doesn't support SHA256/SHA512.  Sigh.
    $algos = 'des';
  }

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/test_rsa_key.pub');
  my $rsa_rfc4716_key = File::Spec->rel2abs('t/etc/modules/mod_passwd_update/authorized_rsa_keys');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_passwd_update.c' => {
        PasswordUpdateEngine => 'on',
        PasswordUpdateLog => $setup->{log_file},
        PasswordUpdateAuthUserFiles => "$setup->{auth_user_file} $new_auth_user_file",
        PasswordUpdateAlgorithms => $algos,
      },

      'mod_sftp.c' => {
        SFTPEngine => 'on',
        SFTPLog => $setup->{log_file},
        SFTPHostKey => $rsa_host_key,
        SFTPAuthorizedUserKeys => 'file:~/.authorized_keys',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Order of directives matters here, thus why we add these lines last.
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh "AuthUserFile $new_auth_user_file\n";
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Password authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();

      # Now login again
      $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Password authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /successfully updated password hash for user '$setup->{user}'/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok,
        test_msg("Did not see expected 'no entry found' log messages"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

1;
