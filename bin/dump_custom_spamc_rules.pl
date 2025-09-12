#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use File::Copy;
use File::Path;
use DB();
my $db = DB->db_connect('slave', 'st_config');

my %domains;
my %senders;
my $rules_file = '/usr/spamtagger/share/spamassassin/98_st_custom.cf';
my $rcpt_id = 0;
my $sender_id = 0;

sub set_current_rule ($current_rule) {
  my $current_rule_w = $current_rule;
  $current_rule_w =~ s/\s+/_/;
  $current_rule_w =~ s/-/_/;
  $current_rule_w =~ s/\./_/;

  return ($current_rule, $current_rule_w);
}

# rules to detect if the wanted rule did hit for those recipients (/senders)
sub print_custom_rule ($file, $current_rule, $current_rule_w, $current_sender, @current_rule_domains) {
  my ($rule, $score) = split(' ', $current_rule);
  print $file "meta RCPT_CUSTOM_$current_rule_w ( $rule ";
  if ($current_sender ne '') {
    print $file '&& __SENDER_' .$senders{$current_sender}. ' ';
  }
  my $global = 0;
  my $rcpt_string = "&& (";
  foreach (@current_rule_domains) {
    if (!defined($_)) {
      $rcpt_string = '';
      last;
    }
    $rcpt_string .= "__RCPT_$_ || "
  }
  if ($rcpt_string) {
    $rcpt_string =~ s/\ \|\|\ $/\) /;
  }
  print $file "$rcpt_string)\n";
  print $file "score RCPT_CUSTOM_$current_rule_w $score\n\n";
  return;
}

# Rules to identify domains
sub print_recipient_rules ($file, $recipient) {

  return if defined($domains{$recipient});
  return if $recipient =~ m/\@__global__/;

  $domains{$recipient} = $rcpt_id;

  $recipient =~ s/\./\\\./g;
  $recipient =~ s/\@/\\\@/g;

  print $file "header __RCPT_TO_$rcpt_id  To =~ /$recipient/i\n";
  print $file "header __RCPT_CC_$rcpt_id  Cc =~ /$recipient/i\n";
  print $file "header __RCPT_BCC_$rcpt_id Bcc =~ /$recipient/i\n";
  print $file "meta   __RCPT_$rcpt_id     ( __RCPT_TO_$rcpt_id || __RCPT_CC_$rcpt_id || __RCPT_BCC_$rcpt_id )\n\n";

  $rcpt_id++;
  return;
}

# Rules to identify senders
sub print_sender_rules($file, $sender) {
  return if ($sender eq '');
  return if defined $senders{$sender};

  $senders{$sender} = $sender_id;
  $sender =~ s/\./\\\./g;
  $sender =~ s/\@/\\\@/g;

  print $file "header __SENDER_$sender_id  From =~ /$sender/i\n";

  $sender_id++;
  return;
}

# first remove file if exists
unlink $rules_file if ( -f $rules_file );


# get list of SpamC exceptions
my @wwlists = $db->get_list_of_hash("SELECT * from wwlists where type = 'SpamC' order by comments ASC, sender DESC");
$db->db_disconnect();
exit if (!@wwlists);
my $RULEFILE;
unless (open($RULEFILE, '>', $rules_file )) {
  print STDERR "Cannot open full log file: $rules_file\n";
  exit();
}

my $current_rule;
my $current_rule_w;
my $current_sender;
my @current_rule_domains;
foreach my $l (@wwlists) {
  my %rule = %{$l};

  # Do SpamC rules for recipients
  print_recipient_rules($RULEFILE, $rule{'recipient'});

  # Do SpamC rules for senders if needed
  if ( defined ($rule{'sender'}) ) {
    $rule{'sender'} =~ s/\s*//g;
  } else {
    $rule{'sender'} = '';
  }
  if ( defined ($rule{'sender'}) && ($rule{'sender'} ne '') ) {
    print_sender_rules($RULEFILE, $rule{'sender'});
  }

  # Make sure rules have the right format or ignore them
  if ( defined ($rule{'comments'}) ) {
    $rule{'comments'} =~ s/^\s*//;
    $rule{'comments'} =~ s/\s*$//;
  }
  next if ( $rule{'comments'} !~ m/[^\s]+ -?\d+\.?\d*/ );

  # Set current variables (rules and senders) to keep track of a change in order to write the rules when needed
  unless (defined($current_rule)) {
    ($current_rule, $current_rule_w) = set_current_rule($rule{'comments'});
  }

  unless (defined($current_sender)) {
    $current_sender = $rule{'sender'};
  }

  my $domain_id;
  my $t = $rule{'recipient'};
  $domain_id = $domains{$t};

  # If we changed rule, in this script rule means SpamC rule name + score
  if ( ($rule{'comments'} ne $current_rule) || ($rule{'sender'} ne $current_sender) ) {

    print_custom_rule($RULEFILE, $current_rule, $current_rule_w, $current_sender, @current_rule_domains);

    ($current_rule, $current_rule_w) = set_current_rule($rule{'comments'});
    $current_sender = $rule{'sender'};
    @current_rule_domains = ();
    push @current_rule_domains, $domain_id;
  } else {
    push @current_rule_domains, $domain_id;
  }
}
print_custom_rule($RULEFILE, $current_rule, $current_rule_w, $current_sender, @current_rule_domains);

close($RULEFILE);
