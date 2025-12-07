#!/usr/bin/env perl

package MailScanner::Cloudmark;

use v5.40;
use warnings;
use utf8;

# TODO: This seems to be unusable. The Cloudmark::CMAE::Client module does not exist, nor can I find a copy of it anywhere.
# There is a plugin Mail::SpamAssassin::Plugin::CMAE referenced in discussion threads, but this source does not appear to be available online. 
# Proofpoint acquired Cloudmark in 2017, so it is likely that the buisness model may have changed around that time.
# The Cloudmark Authority product still exists (https://www.cloudmark.com/en/products/email-messaging-security/cloudmark-authority) but it is unclear to me if it is still available as a SpamAssassin plugin.
# Regardless, it is a commercial add-on which MailCleaner wasn't even bothering to sell anymore, so we certainly won't be offering it unless there is interest from users.

=pod
use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Cloudmark::CMAE::Client qw( :errors );

my $MODULE = "Cloudmark";
my %conf;

sub initialise {
  MailScanner::Log::InfoLog("$MODULE module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$MODULE.cf";
  %Cloudmark::conf = (
    header => "X-$MODULE",
    putHamHeader => 0,
    putSpamHeader => 1,
    maxSize => 0,
    active => 1,
    timeOut => 10,
    server_host => 'localhost',
    server_port => 2703,
    threshold => 0,
    show_categories => 'yes',
    decisive_field => 'none',
    pos_text => '',
    neg_text => '',
    pos_decisive => 0,
    neg_decisive => 0,
    position => 0
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      $Cloudmark::conf{$1} = $2 if (/^(\S+)\s*\=\s*(.*)$/);
    }
    close($CONFIG);
  } else {
    MailScanner::Log::WarnLog("$MODULE configuration file ($configfile) could not be found !");
  }

  if ($Cloudmark::conf{'pos_decisive'} && ($Cloudmark::conf{'decisive_field'} eq 'pos_decisive' || $Cloudmark::conf{'decisive_field'} eq 'both')) {
    $Cloudmark::conf{'pos_text'} = 'position : '.$Cloudmark::conf{'position'}.', spam decisive';
  } else {
    $Cloudmark::conf{'pos_text'} = 'position : '.$Cloudmark::conf{'position'}.', not decisive';
  }
  if ($Cloudmark::conf{'neg_decisive'} && ($Cloudmark::conf{'decisive_field'} eq 'neg_decisive' || $Cloudmark::conf{'decisive_field'} eq 'both')) {
    $Cloudmark::conf{'neg_text'} = 'position : '.$Cloudmark::conf{'position'}.', ham decisive';
  } else {
    $Cloudmark::conf{'neg_text'} = 'position : '.$Cloudmark::conf{'position'}.', not decisive';
  }
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  ## check maximum message size
  my $maxsize = $Cloudmark::conf{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
    MailScanner::Log::InfoLog("Message %s is too big for Cloudmark checks (%d > %d bytes)",
      $message->{id}, $message->{size}, $maxsize);
    $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }

  if ($Cloudmark::conf{'active'} < 1) {
    MailScanner::Log::WarnLog("$MODULE has been disabled");
    $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, "disabled");
    return 0;
  }

  ### check against Cloudmark
  my ($client, $err) = Cloudmark::CMAE::Client->new (
    host    => $Cloudmark::conf{'server_host'},
    timeout => $Cloudmark::conf{'timeOut'},
    port    => $Cloudmark::conf{'server_port'},
  );

  if ($err)  {
    MailScanner::Log::InfoLog("$MODULE server could not be reached for ".$message->{id}."!");
      $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, 'server could not be reached for');
    return 0;
  }

  my @whole_message;
  push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
  push(@whole_message, "\n");
  $message->{store}->ReadBody(\@whole_message, 0);
  my $msg = "";
  foreach my $line (@whole_message) {
    $msg .= $line;
  }

  my $score;
  my $category;
  my $sub_category;
  my $rescan;
  my $analysis;

  $err = $client->score(rfc822 =>  $msg,
    out_score => \$score,
    out_category => \$category,
    out_sub_category => \$sub_category,
    out_rescan => \$rescan,
    out_analysis => \$analysis);

  if ($err) {
    MailScanner::Log::InfoLog("$MODULE scoring failed for ".$message->{id}."!");
    $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, 'scoring failed');
    return 0;
  }

  my $header = "$analysis";
  my $result_str = "";

  if ($Cloudmark::conf{'show_categories'} eq 'yes') {
    my $out_cat;
    my $out_subcat;

    $err = $client->describe_category(category => $category,
      sub_category => $sub_category,
      out_category_desc => \$out_cat,
      out_sub_category_desc => \$out_subcat);

    if ($err) {
      MailScanner::Log::InfoLog("$MODULE Can't extract category/subcat names for ".$message->{id}."!");
    } else {
      # replace all punctuation and wantspace with underscores
      $out_subcat =~ s/[[:punct:]\s]/_/g;
      $result_str = ", xcat=$out_cat/$out_subcat";
    }
  }

  $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}."-cmaetag", $header);

  if ($score > $Cloudmark::conf{'threshold'}) {
    MailScanner::Log::InfoLog("$MODULE result is spam (".$score.$result_str.") for ".$message->{id});
    if ($Cloudmark::conf{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, "is spam (".$score.$result_str.", ".$Cloudmark::conf{pos_text} .")");
    }
    $message->{prefilterreport} .= ", Cloudmark (".$score.$result_str.", ".$Cloudmark::conf{pos_text} .")";

    return 1;
  }
  MailScanner::Log::InfoLog("$MODULE result is not spam (".$score.$result_str.") for ".$message->{id});
  if ($Cloudmark::conf{'putHamHeader'}) {
    $global::MS->{mta}->AddHeaderToOriginal($message, $Cloudmark::conf{'header'}, "is not spam (".$score.$result_str.", ".$Cloudmark::conf{neg_text} .")");
  }
  $message->{prefilterreport} .= ", Cloudmark (".$score.$result_str.", ".$Cloudmark::conf{neg_text} .")";
  return 0;
}

sub dispose {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}

=cut
1;
