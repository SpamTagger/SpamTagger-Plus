#! /usr/bin/perl 

my $i = 0;
my $j = 0;

unlink '/usr/spamtagger/share/spamassassin/double_item_uri.cf';

exit if ( ! -f '/usr/spamtagger/share/spamassassin/double_item_uri.txt' );

open FH_TXT, '<', '/usr/spamtagger/share/spamassassin/double_item_uri.txt';
open RULES, '>', '/usr/spamtagger/share/spamassassin/double_item_uri.cf';
while (<FH_TXT>) {
        $_ =~ s/^\s*//;
        $_ =~ s/\s*$//;
        next if ( $_ =~ m/^#/ );
        my ($w1, $w2) = split(' ', $_);
        next if ( ! defined($w2) );
        print RULES "# auto generated rule to prevent links containing both $w1 and $w2\n";
        print RULES "uri __ST_URI_DBL_ITEM_$i /$w1.*$w2/i\n";
        $j = $i;
        $i++;
        print RULES "uri __ST_URI_DBL_ITEM_$i /$w2.*$w1/i\n";

        print RULES "\nmeta ST_URI_DBL_ITEM_$j ( __ST_URI_DBL_ITEM_$j || __ST_URI_DBL_ITEM_$i )\n";
        print RULES "describe ST_URI_DBL_ITEM_$j Link containing both $w1 and $w2\n";
        print RULES "score ST_URI_DBL_ITEM_$j 7.0\n\n";
        $i++;
}
close FH_TXT;
close RULES;
