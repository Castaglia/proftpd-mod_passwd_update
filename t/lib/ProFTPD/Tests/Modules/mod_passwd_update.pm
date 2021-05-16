package ProFTPD::Tests::Modules::mod_passwd_update;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use Cwd;
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

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub touch_file {
  my $path = shift;

  if (open(my $fh, "> $path")) {
    unless (close($fh)) {
      die("Can't write $path: $!");
    }

  } else {
    die("Can't open $path: $!");
  }

  unless (chmod(0640, $path)) {
    die("Can't set perms on $path: $!");
  }
}

sub passwd_update_unknown_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'passwd_update');

  my $new_auth_user_file = $setup->{auth_user_file};
  $new_auth_user_file .= '.new';

  # Make sure the new auth file exists, even if blank.
  touch_file($new_auth_user_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $new_auth_user_file,
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

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

  # Make sure the new auth file exists, even if blank.
  touch_file($new_auth_user_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $new_auth_user_file,
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

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

  # Make sure the new auth file exists, even if blank.
  touch_file($new_auth_user_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $new_auth_user_file,
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

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

  # Make sure the new auth file exists, even if blank.
  touch_file($new_auth_user_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $new_auth_user_file,
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

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

  # Make sure the new auth file exists, even if blank.
  touch_file($new_auth_user_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'passwd_update:20 passwd_update.file:20 passwd_update.lock:20 passwd_update.passwd:20 passwd_update.salt:20',

    AuthUserFile => $new_auth_user_file,
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

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

1;
