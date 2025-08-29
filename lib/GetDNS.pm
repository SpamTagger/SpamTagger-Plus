package GetDNS;

use v5.40;
use warnings;
use utf8;

# Avoid warnings for the temporary use of >64bit numbers
no warnings qw ( portable overflow ); ## no critic
use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Net::DNS;
use Net::CIDR qw( cidradd cidr2range range2cidr );
use Math::Int128 qw( int128 );
use Data::Validate::IP;

our $debug = 0;

sub new ($class = "GetDNS") {
  my $resolver = Net::DNS::Resolver->new;
  my $validator = Data::Validate::IP->new;

  my $this = {
    'resolver' => $resolver,
    'validator' => $validator,
    'recursion' => 1
  };
  return bless $this, $class;
}

sub dumper ($this, $raw = '', $args = {}) {
  return () unless ($raw);

  $args->{'dumper'} = 'unknown' unless (defined($args->{'dumper'}));
  $args->{'log'} = '/var/spamtagger/log/spamtagger/dumper.log' unless (defined($args->{'log'}));

  # Disabling recursion in order to utilize caching
  my $recursion = $this->{recursion};
  $this->{recursion} = 0;

  chomp($raw);
  my @lines;
  foreach my $line (split("\n", $raw)) {
    $line =~ s/#.*//;
    $line =~ s/([\s\n\r;,])+/ /g;
    push(@lines, split(" ", $line));
  }

  my %cache;
  my @list;
  my @hostnames;
  foreach my $line (@lines) {
    # Some fields allow for a hostname which should not be resolved to IPs
    # Push without looking up DNS info
    if ($line =~ m/^([a-z0-9\-*]+\.)+[a-z]*$/) {
      push(@hostnames,$line);
    # Ignore blank lines
    } elsif ($line =~ m/^\s*$/) {
      next;
    } else {
      $cache{$line} = undef;
    }
  }

  my @invalid;
  my @exceptions;
  my $continue;
  do {
    foreach my $item (keys %cache) {
      if ($item eq '*') {
        $this->{recursion} = $recursion;
        return ( '::0/0', '0.0.0.0/0' );
      } elsif ($item =~ m/\*/) {
        push(@invalid,$item);
        delete($cache{$item});
      } elsif ($item =~ m#^\!(.*)$#) {
        push(@exceptions, $1);
        delete($cache{$item});
      } elsif (defined($cache{$item})) {
        next;
      } elsif ($item =~ m#\*#) {
        $cache{$item} = $item;
      } elsif ($item =~ m#/\d+$#) {
        $cache{$item} = $item;
      } elsif ($this->validIP4($item)) {
        $cache{$item} = $item.'/32';
      } elsif ($this->validIP6($item)) {
        $cache{$item} = $item.'/128';
      } elsif ($item =~ m#/a$#i) {
        unless(defined($cache{$item})) {
          my $a = $item;
          $a =~ s#/a$##i;
          foreach ($this->get_a($a)) {
            unless (defined($cache{$_})) {
              $cache{$_} = undef;
            }
          }
          $cache{$item} = 'cached';
        }
      } elsif ($item =~ m#/aaaa$#i) {
        unless(defined($cache{$item})) {
          my $aaaa = $item;
          $aaaa =~ s#/aaaa$##i;
          foreach ($this->get_aaaa($aaaa)) {
            unless (defined($cache{$_})) {
              $cache{$_} = undef;
            }
          }
          $cache{$item} = 'cached';
        }
      } elsif ($item =~ m#/mx$#i) {
        unless(defined($cache{$item})) {
          my $mx = $item;
          $mx =~ s#/mx$##i;
          foreach ($this->get_mx($mx)) {
            unless (defined($cache{$_})) {
              $cache{$_} = undef;
            }
          }
          $cache{$item} = 'cached';
        }
      } elsif ($item =~ m#/spf$#i) {
        unless(defined($cache{$item})) {
          my $spf = $item;
          $spf =~ s#/spf$##i;
          my @records = $this->get_spf($spf);
          foreach (@records) {
            unless (defined($cache{$_})) {
              $cache{$_} = undef;
            }
          }
          $cache{$item} = 'cached';
        }
      } else {
        push(@invalid,$item);
        delete($cache{$item});
      }
    }

    $continue = 0;
    foreach my $key (keys %cache) {
      unless (defined($cache{$key})) {
        $continue = 1;
      }
    }
  } while ($continue);

  if (scalar(@invalid)) {
    my $fh;
    if (open($fh, '>>', $args->{'log'})) {
      print($fh "Did not understand hostlist entries '" .
        join("', '",@invalid)."' in '$args->{'dumper'}'\n");
      close($fh);
    }
  }

  foreach (keys %cache) {
    if ($cache{$_} eq 'cached') {
      next;
    } else {
      push(@list,$cache{$_});
    }
  }

  if (scalar(@exceptions)) {
    @exceptions = $this->dumper(join(' ',@exceptions));
  }

  @list = $this->simplify(\@list,\@exceptions);
  push(@list,@hostnames);

  $this->{recursion} = $recursion;
  return @list;
}

sub get_a ($this, $target) {
  my $res = $this->{'resolver'}->query($target, 'A');
  if (defined($res->{'answer'}->[0]->{'address'})) {
    return ($res->answer)[0]->address;
  } elsif (defined($res->{'answer'}->[0]->{'cname'})) {
    return $this->get_a(join('.',@{$res->{'answer'}->[0]->{'cname'}->{'label'}}));
  } else {
    return ();
  }
}

sub get_aaaa ($this, $target) {
  my $res = $this->{'resolver'}->query($target, 'AAAA');
  return ($res->answer)[0]->address if ($res);
  return ();
}

sub get_mx ($this, $target) {
  my @res  = mx($this->{'resolver'}, $target);

  my @ips = ();
  if (@res) {
    if ($this->{'recursion'}) {
      foreach (@res) {
        @ips = (
          @ips,
          $this->get_a($_->exchange),
          $this->get_aaaa($_->exchange)
        );
      }
    } else {
      foreach (@res) {
        push(@ips,$_->exchange.'/a');
        push(@ips,$_->exchange.'/aaaa');
      }
    }
  }
  return $this->uniq(@ips);
}

sub get_spf ($this, $target) {
  my $res  = $this->{'resolver'}->query($target, 'TXT');

  return () unless ($res);

  my @blocks;
  foreach ($res->answer) {
    if ($_->{'txtdata'}->[0]->[0] =~ /^v=spf/) {
      my $whole;
      if (scalar(@{$_->{'txtdata'}}) >= 1) {
        foreach my $part (@{$_->{'txtdata'}}) {
          $whole .= $part->[0];
        }
      } else {
        $whole = $_->{'txtdata'}->[0]->[0];
      }
      @blocks = split(' ', $whole);
      last;
    }
  }

  my @ips;
  foreach (@blocks) {
    if ($_ =~ m/^[\?\-\~]/) {
      next;
    } elsif ($_ =~ m/\+?(v=spf.|all|ptr)$/i) {
      next;
    } elsif ($_ =~ m/^exists:(.*)/i) {
      print STDERR "Cannot dump 'exists' argument '$_'.\n";
    } elsif ($_ =~ m/%\{/) {
      print STDERR "Cannot dump macro argument '$_'.\n";
    } elsif ($_ =~ m/^\+?a$/i) {
      if ($this->{'recursion'}) {
        push(@ips,$this->get_a($target));
      } else {
        push(@ips,$target.'/a');
      }
    } elsif ($_ =~ m/^\+?a:(.*)/i) {
      my $a = $1;
      if ($this->{'recursion'}) {
        push(@ips,$this->get_a($a));
      } else {
        push(@ips,$a.'/a');
      }
    } elsif ($_ =~ m/^\+?aaaa$/i) {
      if ($this->{'recursion'}) {
        push(@ips,$this->get_aaaa($target));
      } else {
        push(@ips,$target.'/aaaa');
      }
    } elsif ($_ =~ m/^\+?aaaa:(.*)/i) {
      my $aaaa = $1;
      if ($this->{'recursion'}) {
        push(@ips,$this->get_aaaa($aaaa));
      } else {
        push(@ips,$aaaa.'/aaaa');
      }
    } elsif ($_ =~ m/^\+?mx$/i) {
      if ($this->{'recursion'}) {
        push(@ips,$this->get_mx($target));
      } else {
        push(@ips,$target.'/mx');
      }
    } elsif ($_ =~ m/^\+?mx:(.*)/i) {
      my $mx = $1;
      if ($this->{'recursion'}) {
        push(@ips,$this->get_mx($mx));
      } else {
        push(@ips,$mx.'/mx');
      }
    } elsif ($_ =~ m/^\+?ipv?[46]:(.*)/i) {
      push(@ips,$1);
    } elsif ($_ =~ m/\+?include:(.*)/i) {
      my $include = $1;
      if ($this->{'recursion'}) {
        push(@ips,$this->get_spf($include));
      } else {
        push(@ips,$include.'/spf');
      }
    } elsif ($_ =~ m/\+?redirect=(.*)/i) {
      my $redirect = $1;
      if ($this->{'recursion'}) {
        push(@ips,$this->get_spf($redirect));
      } else {
        push(@ips,$redirect.'/spf');
      }
    } else {
      print("Unrecognized pattern $_\n");
    }
  }

  return $this->uniq(@ips);
}

sub valid_ip4 ($this, $target) {
  return $this->{'validator'}->is_ipv4($target);
}

sub valid_ip6 ($this, $target) {
  return $this->{'validator'}->is_ipv6($target);
}

sub in_ip_list ($this, $target, @ips) {
  my $version;
  if ($this->{'validator'}->is_ipv4($target)) {
    foreach my $range (@ips) {
      unless ($this->{'validator'}->is_ipv4((split('/',$range))[0])) {
        next;
      }
      unless ($range =~ m#/\d+$#) {
        $range .= '/32';
      }
      if ($this->{'validator'}->is_innet_ipv4($target,$range)) {
        return 1;
      }
    }
  } elsif ($this->{'validator'}->is_ipv6($target)) {
    foreach my $range (@ips) {
      unless ($this->{'validator'}->is_ipv6((split('/',$range))[0])) {
        next;
      }
      unless ($range =~ m#/\d+$#) {
        $range .= '/128';
      }
      if ($this->{'validator'}->is_innet_ipv4($target,$range)) {
        return 1;
      }
    }
  } else {
    die "Invalid IP $target\n";
  }
  return 0;
}

sub simplify ($this, $list, $exceptions) {
  my ($wanted4, $wanted6) = $this->merge($list);

  return ( @{$wanted4}, @{$wanted6} ) unless (scalar(@{$exceptions}));

  my ($unwanted4, $unwanted6) = $this->merge($exceptions);

  my @unwanted4 = @{$unwanted4};
  my @wanted4 = @{$wanted4};
  foreach my $block (cidr2range(@unwanted4)) {
    my ($ubottom, $utop) = split('-',$block);
    my @new_wanted;
    while (scalar(@wanted4)) {
      my $current = shift(@wanted4);
      my ($wbottom, $wtop) = split('-',(cidr2range($current))[0]);
      my $string;
      my $continue = 1;
      # No overlap
      if (ip4todec($ubottom) > ip4todec($wtop) || ip4todec($utop) < ip4todec($wbottom)) {
        $string .= "No overlap";
        push( @new_wanted, $current );
      # Starts before, ends after
      } elsif (ip4todec($ubottom) < ip4todec($wbottom) && ip4todec($utop) > ip4todec($wtop)) {
        $string .= "Starts before, ends after";
      # Match beginning
      } elsif (ip4todec($ubottom) == ip4todec($wbottom)) {
        # Match end, remove exact match and jump to next
        if (ip4todec($utop) == ip4todec($wtop)) {
          $string .= "Exact match";
          @new_wanted = ( @new_wanted, @wanted4 );
          $continue = 0;
        # Ends after, remove entire block, but look for other matches
        } elsif (ip4todec($utop) > ip4todec($wtop)) {
          $string .= "Same start, ends after";
        # Ends before, shift start
        } else {
          $string .= "Same start, ends before";
          push( @new_wanted, range2cidr((dectoip4(ip4todec($utop)+1)).'-'.$wtop ));
        }
      # Match end
      } elsif (ip4todec($utop) == ip4todec($wtop)) {
        # Starts before, remove entire block, but look for other matches
        if (ip4todec($ubottom) < ip4todec($wbottom)) {
          $string .= "Starts before, same end";
        # Starts after, shift start
        } else {
          $string .= "Starts after, same end";
          push( @new_wanted, range2cidr($wbottom.'-'.dectoip4(ip4todec($ubottom)-1)) );
          @new_wanted = ( @new_wanted, @wanted4 );
          $continue = 0;
        }
      # Mid-range, add preceding and following blocks
      } elsif (ip4todec($ubottom) > ip4todec($wbottom) && ip4todec($utop) < ip4todec($wtop))  {
        $string .= "Mid-range";
        push( @new_wanted, range2cidr($wbottom.'-'.dectoip4(ip4todec($utop)-1)) );
        push( @new_wanted, range2cidr((dectoip4(ip4todec($utop)+1)).'-'.$wtop ));
        @new_wanted = ( @new_wanted, @wanted4 );
        $continue = 0;
      # Starts after, ends after, shift start; should not be possible
      } elsif (ip4todec($ubottom) > ip4todec($wbottom)) {
        $string .= "INVALID, starts after and continues";
        push( @new_wanted, range2cidr($wbottom.'-'.dectoip4(ip4todec($ubottom)-1)) );
      # Starts before, ends before, push start; should not be possible
      } elsif (ip4todec($utop) < ip4todec($wtop)) {
        $string .= "INVALID, Starts before, ends mid-way";
        push( @new_wanted, range2cidr(dectoip4(ip4todec($utop)+1)).'-'.$wtop );
      # Default should not ever hit
      } else {
        $string .= "This should not be possible";
      }
      if ($debug) {
        if (defined($string)) {
          print "unwanted: $block, wanted: $wbottom-$wtop - $string\n";
        } else {
          print "unwanted: $block, wanted: $wbottom-$wtop - No match\n";
        }
      }
      unless ($continue) {
        last;
      }
    }
    @wanted4 = @new_wanted;
  }

  my @unwanted6 = @{$unwanted6};
  my @wanted6 = @{$wanted6};
  foreach my $block (cidr2range(@unwanted6)) {
    my ($ubottom, $utop) = split('-',$block);
    my @new_wanted;
    while (scalar(@wanted6)) {
      my $current = shift(@wanted6);
      my ($wbottom, $wtop) = split('-',(cidr2range($current))[0]);
      my $string;
      my $continue = 0;
      # No overlap
      if (ip6todec($ubottom) > ip6todec($wtop) || ip6todec($utop) < ip6todec($wbottom)) {
        $string .= "No overlap";
        push( @new_wanted, $current );
      # Starts before, ends after
      } elsif (ip6todec($ubottom) < ip6todec($wbottom) && ip6todec($utop) > ip6todec($wtop)) {
        $string .= "Starts before, ends after";
      # Match beginning
      } elsif (ip6todec($ubottom) == ip6todec($wbottom)) {
        # Match end, remove exact match and jump to next
        if (ip6todec($utop) == ip6todec($wtop)) {
          $string .= "Exact match";
          @new_wanted = ( @new_wanted, @wanted6 );
          $continue = 0;
        # Ends after, remove entire block, but look for other matches
        } elsif (ip6todec($utop) > ip6todec($wtop)) {
          $string .= "Same start, ends after";
        # Ends before, shift start
        } else {
          $string .= "Same start, ends before";
          push( @new_wanted, range2cidr((dectoip6(ip6todec($utop)+1)).'-'.$wtop ));
        }
      # Match end
      } elsif (ip6todec($utop) == ip6todec($wtop)) {
        # Starts before, remove entire block, but look for other matches
        if (ip6todec($ubottom) < ip6todec($wbottom)) {
        $string .= "Starts before, same end";
        # Starts after, shift start
        } else {
        $string .= "Starts after, same end";
          push( @new_wanted, range2cidr($wbottom.'-'.dectoip6(ip6todec($ubottom)-1)) );
          @new_wanted = ( @new_wanted, @wanted6 );
          $continue = 0;
        }
      # Mid-range, add preceding and following blocks
      } elsif (ip6todec($ubottom) > ip6todec($wbottom) && ip6todec($utop) < ip6todec($wtop))  {
        $string .= "Mid-range";
        push( @new_wanted, range2cidr($wbottom.'-'.dectoip6(ip6todec($utop)-1)) );
        push( @new_wanted, range2cidr((dectoip6(ip6todec($utop)+1)).'-'.$wtop ));
        @new_wanted = ( @new_wanted, @wanted6 );
        $continue = 0;
      # Starts after, ends after, shift start; should not be possible
      } elsif (ip6todec($ubottom) > ip6todec($wbottom)) {
        $string .= "INVALID, starts after and continues";
        push( @new_wanted, range2cidr($wbottom.'-'.dectoip6(ip6todec($ubottom)-1)) );
      # Starts before, ends before, push start; should not be possible
      } elsif (ip6todec($utop) < ip6todec($wtop)) {
        $string .= "INVALID, Starts before, ends mid-way";
        push( @new_wanted, range2cidr(dectoip6(ip6todec($utop)+1)).'-'.$wtop );
      # Default should not ever hit
      } else {
        $string .= "This should not be possible";
      }
      if ($debug) {
        if (defined($string)) {
          print "unwanted: $block, wanted: $wbottom-$wtop - $string\n";
        } else {
          print "unwanted: $block, wanted: $wbottom-$wtop - No match\n";
        }
      }
      unless ($continue) {
        last;
      }
    }
    @wanted6 = @new_wanted;
  }

  return ( @wanted4, @wanted6 );
}

sub merge ($this, $list) {
  my (@ip4, @ip6);
  foreach (@{$list}) {
    if ($_ =~ m/:/) {
      @ip6 = cidradd($_,@ip6);
    } else {
      @ip4 = cidradd($_,@ip4);
    }
  }
  return ( \@ip4, \@ip6 );
}

sub ip4todec ($ip4) {
  my @bytes = split /\./, $ip4;
  return ($bytes[0] << 24) + ($bytes[1] << 16) + ($bytes[2] << 8) + $bytes[3];
}

sub dectoip4 ($decimal) {
  my @bytes;
  push @bytes, ($decimal & 0xff000000) >> 24;
  push @bytes, ($decimal & 0x00ff0000) >> 16;
  push @bytes, ($decimal & 0x0000ff00) >>  8;
  push @bytes, ($decimal & 0x000000ff);
  return join '.', @bytes;
}

sub ip6todec ($ip6) {
  my @bytes = split(/:/, expandip6($ip6));
  my $decimal = 0;
  return (int128(hex($bytes[0])) << 112) + (int128(hex($bytes[1])) << 96) + (int128(hex($bytes[2])) << 80) + (int128(hex($bytes[3])) << 64) + (hex($bytes[4]) << 48) + (hex($bytes[5]) << 32) + (hex($bytes[6]) << 16) + hex($bytes[7]);
}

sub dectoip6 ($decimal) {
  $decimal = int128($decimal);
  my @bytes;
  push( @bytes, sprintf("%x", ($decimal & 0xffff0000000000000000000000000000) >> 112) );
  push( @bytes, sprintf("%x", ($decimal & 0x0000ffff000000000000000000000000) >>  96) );
  push( @bytes, sprintf("%x", ($decimal & 0x00000000ffff00000000000000000000) >>  80) );
  push( @bytes, sprintf("%x", ($decimal & 0x000000000000ffff0000000000000000) >>  64) );
  push( @bytes, sprintf("%x", ($decimal & 0x0000000000000000ffff000000000000) >>  48) );
  push( @bytes, sprintf("%x", ($decimal & 0x00000000000000000000ffff00000000) >>  32) );
  push( @bytes, sprintf("%x", ($decimal & 0x000000000000000000000000ffff0000) >>  16) );
  push( @bytes, sprintf("%x", ($decimal & 0x0000000000000000000000000000ffff)       ) );
  return join ':', @bytes;
}

sub expandip6 ($ip) {
  $ip = "0$ip" if ($ip =~ m/^:/);
  $ip .= "0" if ($ip =~ m/:$/);
  if ($ip =~ m/::/) {
    my $missing = '0:' x (9-(scalar(split(/:/, $ip))));
    $ip =~ s/::/:$missing/;
  }
  return $ip;
}

sub uniq ($this, @ips) {
  my %uniq_ips = map { $_ => } @ips;
  return keys(%uniq_ips);
}

1;
