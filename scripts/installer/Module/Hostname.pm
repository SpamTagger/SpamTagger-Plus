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

package Module::Hostname;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib";
use lib "/usr/spamtagger/scripts/installer/";
use DialogFactory();
use InputValidator qw( validate );

sub new($class) {
  my $this = {
    hostnamefile => "/etc/hostname",
    hostsfile => "/etc/hosts"
  };

  return bless $this, $class;
}

sub run($this) {
  my $dfact = DialogFactory->new('InLine');
  my $dlg = $dfact->simple();
  $dlg->clear();

  my $current = `hostnamectl hostname`;
  chomp($current);
  $current //= 'spamtagger';
  $dlg->build('Enter the new hostname', $current);
  my $fqdn = $dlg->display();

  if (validate('fqdn', $fqdn)) {
    my $ret = system("hostnamectl set-hostname $fqdn 2>/dev/null");
    if ( $ret ) {
      `echo $fqdn > $this->{hostnamefile}`
    }
    `sed -i '/127\.0\.0\.1/d' $this->{hostsfile}`;
    my $name = '';
    if ($fqdn =~ m/^(\w+)\..*/) {
      $name .= " $1";
    }
    `echo 127.0.0.1 localhost $fqdn $name >> $this->{hostsfile}`;
    `sed -i '/HOSTNAME/d' /etc/spamtagger.conf`;
    `echo "HOSTNAME = $fqdn" >> /etc/spamtagger.conf`;
    if (-d "/var/spamtagger/spool/mariadb_source") {
      `echo "UPDATE httpd_config SET servername = '$fqdn';" | /usr/spamtagger/bin/st_mariadb -s st_config`;
      `systemctl restart apache2`;
    }
  } else {
    print("Invalid hostname: $fqdn\n");
  }
  return;
}

1;
