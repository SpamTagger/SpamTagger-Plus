#!/usr/bin/env perl
## largely inspired and copied from Julian Field's work for the SpamAssassin cache in SA.pm

package MailScanner::SpamCache;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Compress::Zlib;

my %conf;
my $cachedbh;

my $spam_cache_life     = 5*60;     # Lifetime of low-scoring spam from first seen
my $expire_frequency   = 10*60;    # How often to run the expiry of the cache

my $next_cache_expire;

sub initialise {
  MailScanner::Log::InfoLog("Initializing SpamCache...");

  %SpamCache::conf = (
    cache_useable => 0
  );

  unless (MailScanner::Config::IsSimpleValue('usespamcache') && MailScanner::Config::Value('usespamcache')) {
    MailScanner::Log::WarnLog("SpamCache disable by config");
    return 1;
  }

  unless (eval { "require DBD::SQLite" }) {
    MailScanner::Log::WarnLog("WARNING: You are trying to use the SpamAssassin cache but your DBI and/or DBD::SQLite Perl modules are not properly installed!");
    return 1;
  }

  unless (eval { "require Digest::MD5" }) {
    MailScanner::Log::WarnLog("WARNING: You are trying to use the SpamAssassin cache but your Digest::MD5 Perl module is not properly installed!");
    return 1;
  }
  
  ## init db
  my $spamcachepath = MailScanner::Config::Value('spamcachedatabasefile');

  ## connect to db
  $MailScanner::SpamCache::cachedbh = DBI->connect("dbi:SQLite:$spamcachepath","","",{PrintError=>0,InactiveDestroy=>1});
  unless ( $MailScanner::SpamCache::cachedbh ) {
    MailScanner::Log::WarnLog("WARNING: Could not connect or create database at: $spamcachepath");
    return 1;
  }

  ## create structure (silent when already created)
  $MailScanner::SpamCache::cachedbh->do("CREATE TABLE cache (md5 TEXT, count INTEGER, last TIMESTAMP, first TIMESTAMP, spamreport BLOB, virusinfected INT)");
  $MailScanner::SpamCache::cachedbh->do("CREATE UNIQUE INDEX md5_uniq ON cache(md5)");
  $MailScanner::SpamCache::cachedbh->do("CREATE INDEX last_seen_idx ON cache(last)");
  $MailScanner::SpamCache::cachedbh->do("CREATE INDEX first_seen_idx ON cache(first)");

  MailScanner::Log::InfoLog("Using spam results cache in: $spamcachepath");
  $SpamCache::conf{cache_useable} = 1;

  set_cache_times();
  cache_expire();

  return 1;
}

## called per message ##
sub is_useable {
  return  $SpamCache::conf{cache_useable};
}

sub check_cache ($md5) {
  return unless ($SpamCache::conf{cache_useable});

  my($sql, $sth);
  $sql = "SELECT md5, count, last, first, spamreport FROM cache WHERE md5=?";
  my $hash = $MailScanner::SpamCache::cachedbh->selectrow_hashref($sql,undef,$md5);

  if (defined($hash)) {
    $sql = "UPDATE cache SET count=count+1, last=strftime('%s','now') WHERE md5=?";
    $sth = $MailScanner::SpamCache::cachedbh->prepare($sql);
    $sth->execute($md5);
    return $hash;
  } else {
    return;
  }
}

sub cache_result ($md5, $spamreport) {

  return unless ($SpamCache::conf{cache_useable});

  my $dbh = $MailScanner::SpamCache::cachedbh;

  my $sql = "INSERT INTO cache (md5, count, last, first, spamreport) VALUES (?,?,?,?,?)";
  my $sth = $dbh->prepare($sql);
  my $now = time;
  $sth->execute($md5,1,$now,$now, $spamreport);
  return;
}

## called per batch ##
sub check_for_cache_expire ($this) {
  return if (!$SpamCache::conf{cache_useable});

  cache_expire() if $next_cache_expire<=time;
  return;
}

sub add_virus_stats ($message) {
  return unless ($SpamCache::conf{cache_useable});

  my $sth = $MailScanner::SpamCache::cachedbh->prepare('UPDATE cache SET virusinfected=? WHERE md5=?');
    $sth->execute($message->{virusinfected},
    $message->{md5}
  ) or MailScanner::Log::WarnLog($DBI::errstr);
  return;
}

## Internal calls
# Set all the cache expiry timings from the cachetiming conf option
sub set_cache_times {
  my $line = MailScanner::Config::Value('spamcachetiming');
  $line =~ s/^\D+//;
  return unless $line;
  my @numbers = split /\D+/, $line;
  return unless @numbers;

  $spam_cache_life     = $numbers[0] if $numbers[0];
  $expire_frequency   = $numbers[1] if $numbers[1];
  return;
}

# Expire records from the cache database
sub cache_expire ($expire1 = $spam_cache_life) {
  return unless (is_useable());

  my $sth = $MailScanner::SpamCache::cachedbh->prepare(
    "DELETE FROM cache WHERE ( first<=(strftime('%s','now')-?) )"
  );
  MailScanner::Log::DieLog("Database complained about this: %s. I suggest you delete your %s file and let me re-create it for you", $DBI::errstr, MailScanner::Config::Value("spamcache")) unless $sth;
  my $rows = $sth->execute($expire1);
  $sth->finish;

  MailScanner::Log::InfoLog("Expired %s records from the spam cache", $rows) if $rows>0;

  # This is when we should do our next cache expiry (20 minutes from now)
  $next_cache_expire = time + $expire_frequency;
  return;
}

1;
