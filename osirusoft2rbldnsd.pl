#! /usr/bin/perl -w
# $Id$
# This (somewhat hackish) script converts relays.osirusoft.com's bind zone file
# to rbldnsd format (as `combined' dataset).
# Note this script does NOT keep "metadata", i.e. all the records
#
use strict;

my ($ip, $sub, $a, $txt, $sa);
my $last = '';

my %zones = ( # A RRs for subzones
 dialups => '3',
 spamsources => '4',
 spews => '4',
 spamhaus => '6',
 spamsites => '6',
 proxy => '9',
 socks => '9',
);
my %zstats;
my $r;

$_ = <>;
while(defined $_) {
  if (/^((\d+)\.(\d+)\.(\d+)\.(\d+)\.([a-z]+) in )A ([\d.]+)/) {
    $ip = "$5.$4.$3.$2"; $sub = $6; $a = $7;
  }
  elsif (/^(\*\.(\d+)\.(\d+)\.(\d+)\.([a-z]+) in )A ([\d.]+)/) {
    $ip = "$4.$3.$2"; $sub = $5; $a = $6;
  }
  elsif (/^(\*\.(\d+)\.(\d+)\.([a-z]+) in )A ([\d.]+)/) {
    $ip = "$3.$2"; $sub = $4; $a = $5;
  }
  else { $_ = <>; next; }
  if (defined($_ = <>) && substr($_,0,length($1)) eq $1) {
    if (/ in TXT "(.*)"/) { $txt = $1; }
    else { print STDERR $_; $txt = ""; }
    $_ = <>;
  }
  else { $txt = ""; }
  $a =~ s/^127\.0\.0\.//;
  if ($last ne $sub) {
    die "duplicated zone $sub\n" if $zstats{$sub};
    die "unknown zone $sub\n" unless defined $zones{$sub};
    $zstats{$sub} = 0;
    $r = \$zstats{$sub};
    $sa = $zones{$sub};
    print "\$DATASET ip4set $sub @\n:$sa:\n";
    $last = $sub;
  }
  if ($sa ne $a) { print "$ip :$a:$txt\n"; }
  elsif ($txt ne '') { print "$ip $txt\n"; }
  else { print "$ip\n"; }
  ++$$r;
}

$a = 0;
for $sub (keys %zstats) {
  print STDERR "$sub:\t$zstats{$sub} entries\n";
  $a += $zstats{$sub};
}
print STDERR "Total:\t$a entries\n";
