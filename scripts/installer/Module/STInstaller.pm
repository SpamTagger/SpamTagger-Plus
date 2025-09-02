#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
#   Copyright (C) 2025 John Mertz <git@john.me.tz>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package Module::STInstaller;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib '/usr/spamtagger/lib/';
use lib "/usr/spamtagger/scripts/installer/";
use DialogFactory();
use ReadConfig();

my $conf = {};
$conf = ReadConfig::get_instance() if (-e '/etc/spamtagger.conf');

sub new {
  my $this = {
    dfact => DialogFactory->new('InLine'),
    logfile => '/tmp/spamtagger_install.log',
    conffile => '/etc/spamtagger.conf',
    config_variables => {
      'SRCDIR' => '/usr/spamtagger',
      'VARDIR' => '/var/spamtagger',
      'HOSTID' => undef,
      'DEFAULTDOMAIN' => '',
      'ISMASTER' => 'Y',
      'MYSPAMTAGGERPWD' => undef,
      'HELONAME' => undef,
      'MASTERIP' => undef,
      'MASTERPWD' => undef,
    },
    install_variables => {
      'WEBADMINPWD' => undef,
      'ORGANIZATION' => 'Anonymous',
      'STHOSTNAME' => 'spamtagger',
      'CLIENTTECHMAIL' => 'root@localhost',
    },
    default_configs => {
      'HOSTID' => 1,
      'MYSPAMTAGGERPWD' => 'STPassw0rd',
      'HELONAME' => '',
      'MASTERIP' => '127.0.0.1',
      'MASTERPWD' => 'STPassw0rd',
    }
  };
  # Load variables from existing config file, if set
  if (defined($conf)) {
    foreach (keys(%{$this->{config_variables}})) {
      $this->{config_variables}->{$_} = $conf->get_option($_) if ($conf->get_option($_));
    }
    foreach (keys(%{$this->{install_variables}})) {
      $this->{install_variables}->{$_} = $conf->get_option($_) if ($conf->get_option($_));
    }
  }
  # Override with ENV variables, if set
  foreach (keys(%{$this->{config_variables}})) {
    $this->{config_variables}->{$_} = $ENV{$_} if (defined($ENV{$_}));
  }
  $this->{install_variables}->{'CLIENTTECHMAIL'} = 'support@'.$this->{config_variables}->{'DEFAULTDOMAIN'} if ($this->{config_variables}->{'DEFAULTDOMAIN'} ne '');
  foreach (keys(%{$this->{install_variables}})) {
    $this->{install_variables}->{$_} = $ENV{$_} if (defined($ENV{$_}));
  }
  # Default hostname unless defined above
  my $hostname = `hostname`;
  chomp($hostname);
  $this->{config_variables}->{HELONAME} = $hostname unless (defined($this->{'config_variables'}->{'HELONAME'} && $this->{'config_variables'}->{'HELONAME'} ne ''));
  $this->{install_variables}->{STHOSTNAME} = $hostname unless (defined($this->{'install_variables'}->{'STHOSTNAME'} && $this->{'install_variables'}->{'STHOSTNAME'} ne ''));

  bless $this, 'Module::STInstaller';
  return $this;
}

sub run($this) {
  my @basemenu = (
    'Host ID', 
    'Web admin password', 
    'Database password', 
    'Admin details',
    'Apply configuration', 
    'Exit'
  );
  my $currentstep = 1;
  my $error = '';

  while ($this->do_menu(\@basemenu, \$currentstep, \$error)) {
  }
  return;
}

sub do_menu($this, $basemenu, $currentstep, $error) {
  my $dlg = $this->{'dfact'}->list();
  $dlg->build($$error.'SpamTagger Plus installation', $basemenu, $$currentstep, 1);
  $$error = '';

  my $res = $dlg->display();
  return 0 if $res eq 'Exit';

  if ($res eq 'Host ID') {
    $this->{'config_variables'}->{'HOSTID'} = $this->host_id();
    $$currentstep = 2;
    return 1;
  }

  if ($res eq 'Web admin password') {
    $this->{'install_variables'}->{'WEBADMINPWD'} = $this->web_admin_pwd();
    $$currentstep = 3;
    return 1;
  }

  if ($res eq 'Database password') {
    $this->{'config_variables'}->{'MYSPAMTAGGERPWD'} = $this->database_pwd();
    $this->{'config_variables'}->{'MASTERPWD'} = $this->{'config_variables'}->{'MYSPAMTAGGERPWD'};
    $$currentstep = 4;
    return 1;
  }

  if ($res eq 'Admin details') {
  $this->{'install_variables'}->{'ORGANIZATION'} = $this->organization();
  $this->{'install_variables'}->{'CLIENTTECHMAIL'} = $this->support_email();
    $$currentstep = 5;
    return 1;
  }

  if ($res eq 'Apply configuration') {
    my $ret = $this->apply_configuration;
    if ($ret) {
      if ($ret == 255) {
        $$error = "Fatal error: Failed to open $this->{'conffile'} for writing. Quitting.\n";
      } elsif ($ret == 254) {
        $$error = "Installation abandoned\n";
      } else {
        $$error = "Missing necessary variable. Please follow all earlier steps before applying.\n";
        $$currentstep = $ret;
      } 
    }
    return 0;
  }

  die "Invalid selection: $res\n";
}

sub host_id($this) {
  my $dlg = $this->{'dfact'}->simple();
  my $suggest = $this->{'config_variables'}->{'HOSTID'} //= $this->{'default_configs'}->{'HOSTID'};
  $suggest = 1 if ($suggest eq '');
  $dlg->build('Enter the unique ID of this SpamTagger Plus in your infrastucture', $suggest);
  return $dlg->display();
}

sub web_admin_pwd($this) {
  my $pass1 = '-';
  my $pass2 = '';
  my $pdlg = $this->{'dfact'}->password();
  my $suggest = $this->{'install_variables'}->{'WEBADMINPWD'};
  $suggest //= 'SAME AS DATABASE PASSWORD' if (defined($this->{'config_variables'}->{'MYSPAMTAGGERPWD'}) && $this->{'config_variables'}->{'MYSPAMTAGGERPWD'} ne 'STPassw0rd');
  unless (defined($suggest)) {
    $suggest = 'RANDOM: '.`pwgen -N 1 16`;
    chomp($suggest);
  }
  while ( $pass1 ne $pass2 || $pass1 eq "" || $pass1 eq "STPassw0rd" ) {
    print "Password mismatch, please try again.\n" unless ($pass2 eq '');
    print "Password is require, please try again.\n" if ($pass1 eq '');
    if (defined($suggest)) {
      $pdlg->build('Enter the admin user password for the web interface', $suggest);
    } else {
      $pdlg->build('Enter the admin user password for the web interface', '');
    }
    $pass1 = $pdlg->display();
    if ($pass1 eq 'STPassw0rd') {
      print "Cannot use default password. Please try something else.\n";
    next;
    }
  last if (defined($suggest) && $pass1 eq $suggest && $pass1 ne '');
    $pdlg->build('Please confirm the admin user password', '');
    $pass2 = $pdlg->display();
  }
  $pass1 =~ s/RANDOM: // if ($pass1 =~ m/RANDOM: /);
  return $pass1;
}

sub database_pwd($this) {
  my $pass1 = '-';
  my $pass2 = '';
  my $pdlg = $this->{'dfact'}->password();
  my $suggest = $this->{'config_variables'}->{'MYSPAMTAGGERPWD'};
  $suggest //= 'SAME AS WEB ADMIN PASSWORD' if (defined($this->{'install_variables'}->{'WEBADMINPWD'}) && $this->{'install_variables'}->{'WEBADMINPWD'} ne 'STPassw0rd');
  unless (defined($suggest)) {
    $suggest = 'RANDOM: '.`pwgen -N 1 16`;
    chomp($suggest);
  }
  while ( $pass1 ne $pass2 || $pass1 eq "" || $pass1 eq "STPassw0rd" ) {
    print "Password mismatch, please try again.\n" unless ($pass2 eq '');
    print "Password is require, please try again.\n" if ($pass1 eq '');
    if (defined($suggest)) {
      $pdlg->build('Enter the password for the local database', $suggest);
  } else {
      $pdlg->build('Enter the password for the local database', '');
    }
    $pass1 = $pdlg->display();
    if ($pass1 eq 'STPassw0rd') {
      print "Cannot use default password. Please try something else.\n";
    next;
    }
  last if (defined($suggest) && $pass1 eq $suggest && $pass1 ne '');
    $pdlg->build('Please confirm the local database password', '');
    $pass2 = $pdlg->display();
  }
  $pass1 = $this->{'install_variables'}->{'WEBADMINPWD'} if ($pass1 eq 'SAME AS WEB ADMIN PASSWORD');
  $pass1 =~ s/RANDOM: // if ($pass1 =~ m/RANDOM: /);
  return $pass1;
}

sub organization($this) {
  my $dlg = $this->{'dfact'}->simple();
  my $suggest = $this->{'install_variables'}->{'ORGANIZATION'} || 'Anonymous';
  $dlg->build('Enter your organization name', $suggest);
  $this->{'install_variables'}->{'ORGANIZATION'} = $dlg->display();
  return;
}

sub support_email($this) {
  my $dlg = $this->{'dfact'}->simple();
  my $suggest = $this->{'install_variables'}->{'CLIENTTECHMAIL'} || 'root@localhost';
  $dlg->build('Support email address for your users', $suggest);
  $this->{'install_variables'}->{'CLIENTTECHMAIL'} = $dlg->display();
  return;
}

sub check_variables($this) {
  return 1 unless (defined($this->{'config_variables'}->{'HOSTID'}) && $this->{'config_variables'}->{'HOSTID'} ne '');
  return 2 unless (defined($this->{'install_variables'}->{'WEBADMINPWD'}) && $this->{'install_variables'}->{'WEBADMINPWD'} ne '' && $this->{'install_variables'}->{'WEBADMINPWD'} ne 'STPassw0rd');
  return 3 unless (defined($this->{'config_variables'}->{'MYSPAMTAGGERPWD'}) && $this->{'config_variables'}->{'MYSPAMTAGGERPWD'} ne '' && $this->{'config_variables'}->{'MYSPAMTAGGERPWD'} ne 'STPassw0rd');
  return 3 unless (defined($this->{'config_variables'}->{'MASTERPWD'}) && $this->{'config_variables'}->{'MASTERPWD'} ne 'STPassw0rd');
  return 4 unless (defined($this->{'install_variables'}->{'ORGANIZATION'}) && $this->{'install_variables'}->{'ORGANIZATION'} ne '');
  return 4 unless (defined($this->{'install_variables'}->{'CLIENTTECHMAIL'}) && $this->{'install_variables'}->{'CLIENTTECHMAIL'} ne '');
  return 0;
}

sub write_config($this) {
  if (open(my $fh, '>', $this->{'conffile'})) {
    foreach (keys(%{$this->{'config_variables'}})) {
      if (defined($this->{'config_variables'}->{$_})) {
        print $fh "$_ = $this->{'config_variables'}->{$_}\n";
      }
    }
    close($fh);
  } else {
    return 0;
  }
  return 1;
}

sub apply_configuration($this) {
  my $check = $this->check_variables();
  return $check if ($check);

  my $yndlg = $this->{'dfact'}->yes_no();
  $yndlg->build('WARNING: this operation will overwrite any existing SpamTagger Plus database, if one exists. Do you want to proceed?', 'n');

  return 254 unless ($yndlg->display());
  return 255 unless ($this->write_config());

  unless ($this->is_bootstrapped) {
    print "Configuring Debian...\n";
    `cd $this->{SRCDIR}; debian-bootstrap/install.sh`;
  }
  foreach (keys(%{$this->{'config_variables'}})) {
    $ENV{$_} = $this->{'config_variables'}->{$_};
  }
  foreach (keys(%{$this->{'install_variables'}})) {
    $ENV{$_} = $this->{'install_variables'}->{$_};
  }
  $this->{'install_variables'}->{'WEBADMINPWD'} = $this->{'config_variables'}->{'MYSPAMTAGGERPWD'} if ($this->{'install_variables'} eq 'SAME AS DATABASE PASSWORD');
  print("Running $this->{'config_variables'}->{SRCDIR}/install/install.sh. This will take some time. Installation logs will be saved to /tmp/spamtagger-installer.log\n");
  `LOGFILE="/tmp/spamtagger-installer.log" FORCEDBREINSTALL=1 $this->{'config_variables'}->{SRCDIR}/install/install.sh`;

  my $dlg = $this->{'dfact'}->simple();
  $dlg->clear();

  if (! -e '/var/spamtagger/run/first-time-configuration') {
    if (open(my $fh, '>>', '/var/spamtagger/run/first-time-configuration')) {
      print $fh '';
      close $fh;
    }
  }
  return 0;
}

sub is_bootstrapped($this) {
  # TODO: Update to look for mc-exim instead when available
  # if (-d '/opt/exim4/bin/exim') {
  if (-e '/opt/exim4/bin/exim') {
    return 1;
  }
  return 0;
}

sub is_installed($this) {
  if ( -e '/etc/spamtagger.conf' ) {
    return 1;
  }
  return 0;
}

1;
