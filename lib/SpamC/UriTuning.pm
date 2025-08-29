#!/usr/bin/env perl

package UriTuning;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use parent qw(Mail::SpamAssassin::Plugin);

sub new ($class, $mailsa) {
  # the usual perlobj boilerplate to create a subclass object
  $class = ref($class) || $class;
  my $this = $class->SUPER::new($mailsa);
  bless ($this, $class);

  # then register an eval rule, if desired...
  $this->register_eval_rule ("gglapi_domain");

  # and return the new plugin object
  return $this;
}

sub _domain ($string) {
  $string =~ m/\@(.*)/;
  return $1;
}

# Forbids the use of given strings in a URL that also contains the domain of a recipient
# List of strings in /usr/spamtagger/share/spamassassin/plugins/UriTuning.list
sub gglapi_domain ($this, $permsgstatus, $body, $body_html) {
	my @elems;

	# This module only runs if we have a file of domains to exclude
	return 0 if ( ! -f '/usr/spamtagger/share/spamassassin/plugins/UriTuning.list' );

	# Get list of strings
  my $LIST;
	open($LIST, '<', '/usr/spamtagger/share/spamassassin/plugins/UriTuning.list');
	@elems = <$LIST>;
	close($LIST);
	chomp(@elems);

  # Recipient detection
  my $recipients = lc( $permsgstatus->get('X-SpamTagger-recipients') );
  chomp($recipients);
  my @all_recipients = split(', ', $recipients);
  my %all_recipients_domains;
  foreach my $recip (@all_recipients) {
    $r = _domain($r);
    $all_recipients_domains{$r} = 1;
  }

  # URI detection
  my $uris = $permsgstatus->get_uri_detail_list ();

	# For all URIs
  while (my($uri, $info) = each %{$uris}) {
		# Check if it contains one of the strings
		foreach my $elem (@elems) {
	    if ( $uri =~ m/\Q$elem/ ) {
				# Check if it contains one of the recipient s domain
				foreach my $k (keys %all_recipients_domains) {
          return 1 if ($uri =~ m/\Q$k/);
        }
			}
    }
  }

	# If we are here nothing was found
  return 0;
}

1;
