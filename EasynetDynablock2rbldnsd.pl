#! /usr/bin/perl -w
# $Id$
# 
# A sample script to convert dynablock.easynet.nl bind zone
# (dynablock.txt) into rbldnsd ip4vset form.  Only data gets
# converted, not zone information.  Note this is ip4vset, not
# ip4set, since dynablock.txt contains exclusion entries wich
# can't be presented in ip4set.
#
use strict;

my ($n, $ip, $a, $b);

sub err { print STDERR "$. $_"; }

print ":3:Dynamic IP range listed by easynet.nl DynaBlock - http://dynablock.easynet.nl/errors.html\n\n"

# There are several types of entries (on the right, there is an
# original variant, left column is corresponding ip4vset entry).
#
# *.1.138.209 IN CNAME dialup.ip                  209.138.1
# 1.149.200.207 IN CNAME dialup.ip                207.200.149.1
# $GENERATE 16-19 *.$.5.4 CNAME dialup.ip         4.5.16-4.5.19
# $GENERATE 240-255 $.251.96.67 CNAME nodialup.ip !67.96.251.240-67.96.251.255
# 6.85.128.202 IN CNAME nodialup.ip               !202.128.85.6

while(<>) {

 if (/^([\d.*]+)\s+IN\s+CNAME\s+(no)?dialup\.ip/i) {
   $ip = $1; $n = $2 ? "!" : "";
   if ($ip =~ /^\*\.(\d+)\.(\d+)\.(\d+)$/) { print "$n$3.$2.$1\n"; }
   elsif ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) { print "$n$4.$3.$2.$1\n"; }
   elsif ($ip =~ /^\*\.(\d+)\.(\d+)$/) { print "$n$2.$1\n"; }
   else { err; }
   next;
  }
  if (/^\$GENERATE\s+(\d+)-(\d+)\s+([\d.*\$]+)\s+CNAME\s+(no)?dialup.ip/) {
    $a = $1+0; $b = $2+0; $ip = $3; $n = $4 ? "!" : "";
    if ($a > $b || $b > 255) { err; next; }
    if ($ip =~ /^\$\.(\d+)\.(\d+)\.(\d+)$/) {
      print "$n$3.$2.$1.$a-$3.$2.$1.$b\n";
    }
    elsif ($ip =~ /^\*\.\$\.(\d+)\.(\d+)$/) {
      print "$n$2.$1.$a-$2.$1.$b\n";
    }
    #elsif ($ip =~ /^\*\.\*\.\$\.(\d+)$/) {
    #  print "$n$1.$a-$1.$b\n";
    #} 
    else { err; }
    next;
  }
  if (s/^\s*;/#/) { print unless /^#\s*$/; next; }

  next if /^(\$TTL|@|\s|2\.0\.0\.127|dialup\.ip|\s*$)/; # skip some known lines
  err;
}
