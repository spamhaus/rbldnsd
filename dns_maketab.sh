#! /bin/sh
set -e

# dns_maketab.sh dns.h prefix name
in=$1 prefix=$2 name=$3 tab=${name}_tab

echo "/* $name code table automatically generated from $in */
#include \"dns.h\"
static const struct dns_nameval $tab[] = {"
sed -n 's/^[ 	]\+'$prefix'\([A-Z0-9_]\+\)[ 	]\+=.*/ {'$prefix'\1,"\1"},/p' $in
echo "};
const struct dns_codetab $name = { &$tab, sizeof($tab)/sizeof($tab[0]) };"
