#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use DBI();
use Term::ReadKey;

my %config = readConfig("/etc/spamtagger.conf");

my $slave_dbh = DBI->connect("DBI:mysql:database=st_config;mysql_socket=$config{'VARDIR'}/run/mysql_slave/mysqld.sock",
                                        "spamtagger","$config{'MYSPAMTAGGERPWD'}", {RaiseError => 0, PrintError => 0} );
if (!$slave_dbh) {
	printf ("ERROR: no slave database found on this system.\n");
	exit 1;
}

sub view_slaves {
	my $sth =  $slave_dbh->prepare("SELECT id, hostname, port, ssh_pub_key  FROM slave") or die ("error in SELECT");
	$sth->execute() or die ("error in SELECT");
	my $el=$sth->rows;
	while (my $ref=$sth->fetchrow_hashref()) {
		printf $ref->{'hostname'}."\n";
	}
	$sth->finish();
}

sub readConfig {       # Reads configuration file given as argument.
        my $configfile = shift;
        my %config;
        my ($var, $value);

        open CONFIG, $configfile or die "Cannot open $configfile: $!\n";
        while (<CONFIG>) {
                chomp;                  # no newline
                s/#.*$//;                # no comments
                s/^\*.*$//;             # no comments
                s/;.*$//;                # no comments
                s/^\s+//;               # no leading white
                s/\s+$//;               # no trailing white
                next unless length;     # anything left?
                my ($var, $value) = split(/\s*=\s*/, $_, 2);
                $config{$var} = $value;
        }
        close CONFIG;
        return %config;
}

view_slaves();
