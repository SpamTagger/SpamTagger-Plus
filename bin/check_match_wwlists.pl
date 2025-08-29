#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DB();
use Email();

my @column_names = qw/id sender recipient type comments/;
my @type_order = qw/black white wnews warn/;
my @list_level_order = qw/user domain global/;

my $sender = shift;
my $recipient = shift;

my $matches = get_wlist_matches($sender, $recipient, \@column_names);
if (scalar(@$matches) == 0){
  exit 0;
}

my @sort_order = ("type", "level");
my %sort_hash;
$sort_hash{"type"} = \@type_order;
$sort_hash{"level"} = \@list_level_order;

my $final_list = sort_by($matches, \@sort_order, \%sort_hash);

print_result(\@column_names, $final_list);

## ------

sub sort_by ($entries, $sort_order, $sort_hash) {
  my @output;
  my $order = shift(@$sort_order);

  foreach my $field_value (@{$sort_hash->{$order}}) {
    my @intermediate;
    foreach my $entry (@{$entries}) {
      if ($entry->{$order} eq $field_value){
        push(@intermediate, $entry);
      }
    }

    my $sub_sorted;
    if (@{$sort_order}) {
      $sub_sorted = sort_by(\@intermediate, $sort_order, $sort_hash);
    } else {
      my @id_sorted = sort { $a->{id} <=> $b->{id}} @intermediate;
      $sub_sorted = \@id_sorted;
    }
    push(@output, @$sub_sorted);
  }
  return \@output;
}

sub get_wlist_matches ($sender, $recipient, $column_names) {

  my $db = DB->db_connect('slave', 'st_config');
  my $query_cols = join(",", @$column_names);

  my @recipients = @{get_possible_recipients($recipient)};
  my @str_recipients = map { "recipient='$_'" } @recipients;
  my $query_recipients = join(" OR ", @str_recipients);

  my $query = $db->prepare(qq{SELECT $query_cols FROM wwlists WHERE $query_recipients;});
  my $result = $query->execute();

  my @matches;
  while(my $res = $query->fetchrow_hashref()){
    if (Email::list_match($res->{"sender"}, $sender) && Email::list_match($res->{"recipient"}, $recipient)){
      my $entry_with_level = get_wlist_level($res);
      push(@matches, $entry_with_level);
    }
  }
  $db->db_disconnect;
  return \@matches;
}

sub get_possible_recipients ($recipient) {
  my @recipients;
  push @recipients, $recipient;
  push @recipients, $recipient =~ m/^.+(@.+\..+)$/;
  push @recipients, "";
  return \@recipients;
}

sub get_wlist_level ($entry) {
  my $entry_with_level = $entry;
  if ($entry->{recipient} =~ m/^.+@.+\..+$/){
    $entry_with_level->{level} = "user";
  } elsif ($entry->{recipient} =~ m/^@.+\..+$/){
    $entry_with_level->{level} = "domain";
  } elsif ($entry->{recipient} =~ m/^$/){
    $entry_with_level->{level} = "global";
  } else {
    print("Error getting the type of the entry, exiting...");
    exit 1;
  }
  return $entry_with_level;
}

sub check_column_width ($column_name, $column_value = "", $columns_widths = undef) {
  if (not exists($columns_widths->{$column_name})) {
    $columns_widths->{$column_name} = length($column_value);
  } elsif (length($column_value) > $columns_widths->{$column_name}){
    $columns_widths->{$column_name} = length($column_value);
  }
  return;
}

sub get_columns_widths ($columns_names, $entries_list, $columns_widths) {
  foreach my $column (@$columns_names){
    check_column_width($column, $column, $columns_widths);
    foreach my $entry (@$entries_list){
      check_column_width($column, $entry->{$column}, $columns_widths);
    }
  }
  return;
}

sub format_entry ($entry, $columns_widths, $columns_names) {
  my $format_string = "| %*s ";
  my $return_string = "";
  foreach my $column (@$columns_names){
    if (not defined($entry->{$column})){
      $entry->{$column} = "";
    }
    $return_string = $return_string . sprintf($format_string, -$columns_widths->{$column}, $entry->{$column});
  }
  $return_string = $return_string . "|\n";
  return $return_string;
}

sub print_result ($column_names, $entries, %columns_widths) {
  get_columns_widths($column_names, $entries, \%columns_widths);

  my %header_entry = map {$_ => $_} @$column_names;
  my %line_entry = map {$_ => "-" x $columns_widths{$_}} @$column_names;
  print(format_entry(\%header_entry, \%columns_widths, $column_names));
  print(format_entry(\%line_entry, \%columns_widths, $column_names));
  foreach my $entry (@$entries){
    print(format_entry($entry, \%columns_widths, $column_names));
  }
  print("\n");
  return;
}
