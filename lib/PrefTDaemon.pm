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
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

package PrefTDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use Time::HiRes qw(gettimeofday tv_interval);
use ReadConfig();
use DB();
use Digest::MD5 qw(md5_hex);
use threads();
use threads::shared qw(share);
use PrefClient();

use parent qw(SockTDaemon);

my $prefs_      = &share( {} );
my $wantlists_ = &share( {} );
my $warnlists_  = &share( {} );
my $blocklists_  = &share( {} );
my %stats_ : shared = (
  'prefqueries'      => 0,
  'prefsubqueries'   => 0,
  'cacheprefhits'    => 0,
  'cacheprefexpired' => 0,
  'prefnotcached'    => 0,
  'cachingprefvalue' => 0,
  'backendprefcall'  => 0,
  'wwqueries'        => 0,
  'wwsubqueries'     => 0,
  'cachewwhits'      => 0,
  'cachewwexpired'   => 0,
  'wwnotcached'      => 0,
  'cachingwwvalue'   => 0,
  'backendwwcall'    => 0
);

sub new ($class, $params) {
  my $conf = ReadConfig::get_instance();

  my $spec_this = {
    name              => 'PrefTDaemon',
    socketpath        => $conf->get_option('VARDIR') . "/run/prefdaemon.sock",
    configfile        => $conf->get_option('SRCDIR') . "/etc/spamtagger/prefdaemon.conf",
    pidfile           => $conf->get_option('VARDIR') . "/run/prefdaemon.pid",
    profile           => 0,
    prefork           => 5,
    clean_thread_exit => 1,
    timeout_pref      => 60,
    timeout_ww        => 60,
    backend           => undef,
  };
  $spec_this->{$_} = $params->{$_} foreach (keys(%{$params}));

  my $this = SockTDaemon->new( $spec_this->{'name'}, undef, $spec_this );

  return bless $this, $class;
}

sub init_thread_hook ($this) {
  $this->do_log('PrefDaemon thread initialization...', 'prefdaemon', 'debug');
  $this->connect_backend();

  return 1;
}

sub connect_backend ($this) {
  return 1 if ( defined( $this->{backend} ) && $this->{backend}->ping() );

  $this->{backend} = DB->db_connect( 'replica', 'st_config', 0 );
  if ( $this->{backend}->ping() ) {
    $this->do_log("Connected to configuration database", 'prefdaemon');
    return 1;
  }
  $this->do_log("WARNING, could not connect to configuration database", 'prefdaemon', 'error');
  return 0;
}

sub data_read ($this, $data) {
  $this->do_log("Received datas: $data", 'prefdaemon', 'debug');
  my $ret = 'NOTHINGDONE';

  ## PREF query
  if ( $data =~ m/^PREF\s+([-_.!\$#=*&\@a-z0-9]+)\s+([-_a-z0-9]+)\s*(R)?/i ) {
    my $object = lc($1);
    my $pref   = $2;

    ## recurse will force us to find the domain pref if it's not defined, or explicitely not set for the user
    ## the recurse is a: "if no pref found, then use domain's default"
    my $recurs = 0;
    $recurs = 1 if ( defined($3) && $3 eq 'R' );

    my $result = $this->get_object_preference( $object, $pref, $recurs );
    return $result;
  }

  $this->do_log('BLOCKLIST PREFT'.$data, 'prefdaemon', 'debug');

  ## WANTLIST and WARNLSIT query
  if ( $data =~
m/^(WANT|WARN|BLOCK)\s+([-_.!\/\$+#=*&\@a-z0-9]+)\s+([-_.!\/\$+#=*&a-z0-9]+\@[-_.a-z0-9]+)/i
    )
  {
    my $type   = $1;
    my $object = lc($2);
    my $sender = lc($3);

    $this->add_stat( 'wwqueries', 1 );

    my $result = "NOTLISTED";

    ## first check if global system allows wwlist
    return $result
      if ( $type eq 'BLOCK'
        && !$this->get_object_preference( '_global', 'enable_blocklists' ) );
    return $result
      if ( $type eq 'WANT'
      && !$this->get_object_preference( '_global', 'enable_wantlists' ) );
    return $result
      if ( $type eq 'WARN'
      && !$this->get_object_preference( '_global', 'enable_warnlists' ) );

    ## then check if domain allows wwlist
    my $domain = get_domain($object);
    if ($domain) {
      #return $result
      return $result
        if ( $type eq 'BLOCK'
          && !$this->get_object_preference( $domain, 'enable_blocklists' ) );
      return $result
        if ( $type eq 'WANT'
          && !$this->get_object_preference( $domain, 'enable_wantlists' ) );
      return $result
        if ( $type eq 'WARN'
          && !$this->get_object_preference( $domain, 'enable_warnlists' ) );
    }

    ## if here, then wwlists are allowed
    $result = $this->get_object_ww_list( $type, $object, $sender );

    return $result;
  }

  ## CLEAR command
  if ( $data =~
    m/^CLEAR\s+(PREF|BLOCK|WANT|WARN|STATS)\s+([-_.!\$+#=*&\@a-z0-9]+)?/i )
  {
    my $what   = $1;
    my $object = lc($2);

    return "NOTCLEARED";
  }

  ## GETINTERNALSTATS command
  if ( $data =~ m/^GETINTERNALSTATS/i ) {
    return $this->log_stats();
  }

  return "_UNKNOWNCOMMAND";
}

##################
## utils
sub is_global ($object) {
  return 1 if ( $object =~ /^_global/ );
  return 0;
}

sub is_domain ($object) {
  return 1 if ( $object =~ /^[-_.a-z0-9]+$/ );
  return 0;
}

sub is_email ($object) {
  return 1 if ( $object =~ /^[-_.!\$#=*&\@'`a-z0-9]+\@[-_.a-z0-9]+$/ );
  return 0;
}

sub is_user_id ($object) {
  return 1 if ( $object =~ /^\*\d+$/ );
  return 0;
}

sub get_domain ($object) {
  if ( $object =~ /^[-_.!\$#=*&\@'`a-z0-9]+\@([-_.a-z0-9]+)$/ ) {
    return $1;
  }
  return 0;
}

#######################################################
##  Preferences management
sub get_object_preference ($this, $object, $pref, $recurs) {
  $this->add_stat( 'prefqueries', 1 );

  ## first check if value is already being cached
  my $cachedvalue = $this->get_object_cached_pref( $object, $pref );
  if (
    $cachedvalue !~ m/^_/
    && !(
      $cachedvalue =~ m/^(NOTSET|NOTFOUND)$/
      && ( $recurs || is_domain($object) )
    )
  ) {
    return $cachedvalue;
  }

  my $result = '_BADOBJECT';

  ## if notcached or not defined, fetch pref by type
  if ( is_global($object) ) {
    $result = $this->fetch_global_pref( $object, $pref );
    return $result;
  } elsif ( is_domain($object) ) {
    $result = $cachedvalue;
    if ( $result !~ m/^(NOTSET|NOTFOUND)$/ ) {
      $result = $this->fetch_domain_pref( $object, $pref );
    }
    if ( $result =~ m/^_/ || $result =~ m/NOTFOUND/ ) {
      my $dom = '*';
      $cachedvalue = $this->get_object_cached_pref( $dom, $pref );
      if ( $cachedvalue !~ m/^_/ && $cachedvalue !~ m/NOTFOUND/ ) {
        $this->add_stat( 'prefqueries', 1 );
        return $cachedvalue;
      }
      $result = $this->fetch_domain_pref( $dom, $pref );
    }

    return $result;
  } elsif ( is_email($object) ) {
    $result = $cachedvalue;

    #print STDERR "init pref: $result\n";
    if ( $result !~ m/^(NOTSET|NOTFOUND)$/ ) {
      $result = $this->fetch_email_pref( $object, $pref );

      #print STDERR "got backend email pref: $result\n";
    }

    if ( $result =~ m/^(NOTSET|NOTFOUND)$/ ) {
      my $dom = get_domain($object);
      $cachedvalue = $this->get_object_cached_pref( $dom, $pref );

      #print STDERR "got domain cached pref: $cachedvalue\n";
      if ( $cachedvalue !~ m/^_/ && $cachedvalue !~ m/NOTFOUND/ ) {
        $this->add_stat( 'prefqueries', 1 );
        return $cachedvalue;
      }
      $result = $this->fetch_domain_pref( $dom, $pref );
      if ( $result =~ m/^_/ || $result =~ m/NOTFOUND/ ) {
        $dom = '*';
        $cachedvalue = $this->get_object_cached_pref( $dom, $pref );
        if ( $cachedvalue !~ m/^_/ && $cachedvalue !~ m/NOTFOUND/ ) {
          $this->add_stat( 'prefqueries', 1 );
          return $cachedvalue;
        }
        $result = $this->fetch_domain_pref( $dom, $pref );

        #print STDERR "fetched * pref: $result\n";
      }

      #print STDERR "got domain backend pref for $dom: $result\n";
      $this->add_stat( 'prefqueries', 1 );
      return $result;
    }

    return $result;
  } elsif ( is_user_id($object) ) {
    $result = $cachedvalue;
    return 'NOTIMPLEMENTED';
  }

  return $result;
}

sub get_pref_cache_key ($object, $pref) {
  return md5_hex( $object . "-" . $pref );
}

sub get_object_cached_pref ($this, $object, $pref) {
  my $key = get_pref_cache_key( $object, $pref );

  if ( defined( $prefs_->{$key} )
    && defined( $prefs_->{$key}->{'value'} )
    && defined( $prefs_->{$key}->{'time'} ) )
  {
    lock( %{ $prefs_->{$key} } );
    ## have to check time for expired cached value
    my $deltatime = time() - $prefs_->{$key}->{'time'};

    ## if not expired, then return cached value
    if ( $deltatime < $this->{'timeout_pref'} ) {
      $this->do_log("Cache key hit for: $key ($object, $pref)", 'prefdaemon', 'debug');
      $this->add_stat( 'cacheprefhits', 1 );
      return $prefs_->{$key}->{'value'};
    }
    $this->add_stat( 'cacheprefexpired', 1 );
    $this->do_log("Cache key ($key) too old: $deltatime s.", 'prefdaemon', 'debug');
    return '_CACHEEXPIRED';
  }
  $this->add_stat( 'prefnotcached', 1 );
  $this->do_log("No cache key hit for: $key ($object, $pref)", 'prefdaemon', 'debug');
  return '_NOTCACHED';
}

sub set_object_pref_cache ($this, $object, $pref, $value) {
  my $key = get_pref_cache_key( $object, $pref );
  $prefs_->{$key} = &share({}) unless ( defined( $prefs_->{$key} ) );

  lock( %{ $prefs_->{$key} } );
  $prefs_->{$key}->{'value'} = $value;
  $prefs_->{$key}->{'time'}  = time();
  $this->do_log("Caching value for: $key ($object, $pref)", 'prefdaemon', 'debug');
  $this->add_stat( 'cachingprefvalue', 1 );

  return 1;
}

sub fetch_email_pref ($this, $object, $pref) {
  my $query = "SELECT $pref FROM user_pref p, email e WHERE p.id=e.pref AND e.address='$object'";
  my $result = $this->fetch_backend_pref( $query, $pref );
  $this->add_stat( 'backendprefcall', 1 );
  $this->set_object_pref_cache( $object, $pref, $result );
  return $result;
}

sub fetch_user_pref ($this, $object, $pref) {
  $object =~ s/^\*//g;
  my $query = "SELECT $pref FROM user_pref p, user u WHERE u.id=".$object;
  my $result = $this->fetch_backend_pref( $query, $pref );
  $this->add_stat( 'backendprefcall', 1 );
  $this->set_object_pref_cache( $object, $pref, $result );
  return $result;
}

sub fetch_domain_pref ($this, $object, $pref) {
  $this->add_stat( 'prefsubqueries', 1 );

  $pref = 'enable_wantlists' if ( $pref eq 'has_wantlist' );
  $pref = 'enable_warnlists' if ( $pref eq 'has_warnlist' );
  $pref = 'enable_blocklists' if ( $pref eq 'has_blocklist' );

  my $query = "SELECT $pref FROM domain_pref p, domain d WHERE p.id=d.prefs AND d.name='$object'";
  my $result = $this->fetch_backend_pref( $query, $pref );
  $this->add_stat( 'backendprefcall', 1 );
  $this->set_object_pref_cache( $object, $pref, $result );
  return $result;
}

sub fetch_global_pref ($this, $object, $pref) {
  my $query = "SELECT $pref FROM system_conf, antispam, antivirus, httpd_config";
  my $result = $this->fetch_backend_pref( $query, $pref );
  $this->add_stat( 'backendprefcall', 1 );
  $this->set_object_pref_cache( $object, $pref, $result );
  return $result;
}

sub fetch_backend_pref ($this, $query, $pref) {
  return '_NOBACKEND' if ( !$this->connect_backend() );

  my %res = $this->{backend}->get_hash_row($query);
  return $res{$pref} if ( defined( $res{$pref} ) );

  return 'NOTFOUND';
}

##########################
## WWList management

sub get_ww_cache_key ($object) {
  return md5_hex($object);
}

sub get_object_ww_list ($this, $type, $object, $sender) {
  ## first check if already cached
  my $iscachelisted = $this->get_object_cached_ww( $type, $object, $sender );
  return 'LISTED USER' if ( $iscachelisted eq 'LISTED' );

  my $islisted = '';

  if ( $iscachelisted =~ /^_/ ) {
    ## fetch user list
    $islisted = $this->get_object_backend_ww( $type, $object, $sender );
    return 'LISTED USER' if ( $islisted eq 'LISTED' );
  }

  ## then search for domain list if needed
  my $domain = '@' . get_domain($object);
  if ($domain) {
    $iscachelisted = $this->get_object_cached_ww( $type, $domain, $sender );
    return 'LISTED DOMAIN' if ( $iscachelisted eq 'LISTED' );

    if ( $iscachelisted =~ /^_/ ) {
      ## fetch domain list
      $islisted = $this->get_object_backend_ww( $type, $domain, $sender );
      return 'LISTED DOMAIN' if ( $islisted eq 'LISTED' );
    }
  }

  ## finally search fot global list
  $iscachelisted = $this->get_object_cached_ww( $type, '_global', $sender );
  return 'LISTED GLOBAL' if ( $iscachelisted eq 'LISTED' );

  if ( $iscachelisted =~ /^_/ ) {
    ## fetch global list
    $islisted = $this->get_object_backend_ww( $type, '_global', $sender );
    return 'LISTED GLOBAL' if ( $islisted eq 'LISTED' );
  }

  return 'NOTLISTED';
}

sub get_object_cached_ww ($this, $type, $object, $sender) {
  $this->add_stat( 'wwsubqueries', 1 );
  my $key = get_ww_cache_key($object);

  my $cache_ = $wantlists_;
  if ( $type eq 'WARN' ) { $cache_ = $warnlists_; }
  if ( $type eq 'BLOCK' ) { $cache_ = $blocklists_; }
  if ( defined( $cache_->{$key} )
    && defined( $cache_->{$key}->{'value'} )
    && defined( $cache_->{$key}->{'time'} )
  ) {
    lock( %{ $cache_->{$key} } );
    ## have to check time for expired cached value
    my $deltatime = $this->{'timeout_ww'};
    if ( $cache_->{$key}->{'time'} ) {
      $this->do_log(
        "found WW cache with time: " . $cache_->{$key}->{'time'}, 'prefdaemon', 'debug' );
      $deltatime = time() - $cache_->{$key}->{'time'};
    }

    ## if not expired, then return cached value
    if ( $deltatime < $this->{'timeout_ww'} ) {
      $this->do_log("Cache key hit for: $key ($object)", 'prefdaemon', 'debug');
      $this->add_stat( 'cachewwhits', 1 );

      foreach my $l ( @{ $cache_->{$key}->{'value'} } ) {
        $this->do_log(
          "testing cached WW value for $object: $sender <-> " . $l, 'prefdaemon', 'debug' );
        if ( list_match( $l, $sender ) ) {
          $this->do_log(
            "Found WW cached MATCH for $object: $sender <-> "
              . $l, 'prefdaemon', 'debug' );
          return 'LISTED';
        }
      }
      return 'NOTLISTED';
    }
    $this->add_stat( 'cachewwexpired', 1 );
    $this->do_log("Cache key ($key) too old: $deltatime s.", 'prefdaemon', 'debug');
    return '_CACHEEXPIRED';
  }
  $this->add_stat( 'wwnotcached', 1 );
  $this->do_log("No cache key hit for: $key ($object)", 'prefdaemon', 'debug');
  return '_NOTCACHED';
}

sub get_object_backend_ww ($this, $type, $object, $sender) {
  $type = lc($type);

  $this->add_stat( 'wwsubqueries', 1 );
  my $cache_ = $wantlists_;
  if ( $type eq 'warn' ) { $cache_ = $warnlists_; }
  if ( $type eq 'block' ) { $cache_ = $blocklists_; }

  return '_NOBACKEND' if ( !$this->connect_backend() );
  my $query = "SELECT sender FROM wwlists WHERE recipient='$object' AND type='$type' AND status=1";
  if ( $object eq '_global' ) {
    $query = "SELECT sender FROM wwlists WHERE recipient='$object' OR recipient='' AND type='$type' AND status=1";
  }

  #print STDERR $query."\n";
  my @reslist = $this->{backend}->get_list_of_hash($query);

  $this->add_stat( 'backendwwcall', 1 );

  my $key = get_ww_cache_key($object);

  my $result = 'NOTLISTED';
  $this->create_ww_array_cache( $type, $key );
  foreach my $resh (@reslist) {

    $this->do_log( "testing backend WW entry for $object: $sender: <-> "
      . $resh->{'sender'}, 'prefdaemon', 'debug' );
    $this->add_to_cache( $cache_, $key, $resh->{'sender'} );

    if ( list_match( $resh->{'sender'}, $sender ) ) {
      $this->do_log( "Found WW entry MATCH for $object: $sender <-> "
        . $resh->{'sender'}, 'prefdaemon', 'debug' );
      $result = 'LISTED';
    }
  }

  return $result;
}

sub add_to_cache ($this, $cache, $key, $data) {
  lock $cache;
  push @{ $cache->{$key}->{'value'} }, $data;
  return;
}

sub list_match ($reg, $sender) {
  # Use only the actual address as pattern
  if ($reg =~ /^.*<(.*\@.*\..*)>$/) {
    $reg = $1;
  }
  $reg =~ s/\./\\\./g; # Escape all dots
  $reg =~ s/\@/\\\@/g; # Escape @
  $reg =~ s/\*/\.\*/g; # Glob on all characters when using *
  $reg =~ s/\+/\\\+/g; # Escape +
  $reg =~ s/\|/\\\|/g; # Escape |
  $reg =~ s/\{/\\\{/g; # Escape {
  $reg =~ s/\}/\\\}/g; # Escape }
  $reg =~ s/\?/\\\?/g; # Escape ?
  $reg =~ s/[^a-zA-Z0-9\+.\\\-_=@\*\$\^!#%&'\/\?`{|}~]//g; # Remove unwanted characters
  $reg = '.*' if ( $reg eq "" );
  return 1 if ($sender =~ /$reg/i);
  return 0;
}

sub create_ww_array_cache ($this, $type, $key) {
  my $cache_ = $wantlists_;
  $cache_ = $warnlists_ if ( $type eq 'warn' );
  $cache_ = $blocklists_ if ( $type eq 'block' );

  lock $cache_;
  $cache_->{$key} = &share( {} );
  $cache_->{$key}->{'time'}  = time();
  $cache_->{$key}->{'value'} = &share( [] );

  return 1;
}

##########################
## Stats and counts utils
sub add_stat ($this, $what, $amount) {
  lock %stats_;
  $stats_{$what} = 0 unless ( !defined( $stats_{$what} ) );
  $stats_{$what} += $amount;
  return 1;
}

sub status_hook ($this) {
  my $res = '-------------------'."\n";
  $res .= 'Current statistics:'."\n";
  $res .= '-------------------' ."\n";

  $res .= $this->SUPER::status_hook();
  my $client = PrefClient->new();
  $res .= $client->query('GETINTERNALSTATS');

  $res .= '-------------------' ."\n";

  $this->do_log($res, 'prefdaemon');

  return $res;
}

sub log_stats ($this) {
  lock %stats_;

  my $prefpercencached = 0;
  if ( $stats_{'prefqueries'} > 0 ) {
    $prefpercencached = (
      int(
        ( ( 100 / $stats_{'prefqueries'} ) * $stats_{'cacheprefhits'} )
        * 100
      )
    ) / 100;
  }

  my $wwpercencached = 0;
  if ( $stats_{'wwsubqueries'} > 0 ) {
    $wwpercencached = (
      int(
        ( ( 100 / $stats_{'wwsubqueries'} ) * $stats_{'cachewwhits'} ) *
          100
      )
    ) / 100;
  }

  my $totalqueries = $stats_{'prefqueries'} + $stats_{'wwqueries'};

  my $res = '  Preference queries processed: ' . $stats_{'prefqueries'} . "\n";
  $res .= '  Preference queries cached: ' . $stats_{'cacheprefhits'} . " ($prefpercencached %)\n";
  $res .= '  Preference backend calls: ' . $stats_{'backendprefcall'} . "\n";
  $res .= '  WWlists queries processed: ' . $stats_{'wwqueries'} . "\n";
  $res .= '  WWlists sub queries processed: ' . $stats_{'wwsubqueries'} . "\n";
  $res .= '  WWlists queries cached: ' . $stats_{'cachewwhits'} . " ($wwpercencached %)\n";
  $res .= '  WWLists backend calls: ' . $stats_{'backendwwcall'} . "\n";

  return $res;
}

1;
