#! /usr/bin/awk -f
# A script to generate dns_nametab.c from dns.h
# (various name tables like rtype etc)

BEGIN {
  n = ""
  s = ""
  print "/* file automatically generated */"
  print "#include \"dns.h\""
  print "#include <stdio.h>"
}

/^enum dns_/ {
  n = substr($2,5)
  #print "\n#ifdef gen_" n "tab"
  print "\nconst struct dns_nameval dns_" n "tab[] = {"
  i = 0
  next
}

n != "" && /^[ 	]+DNS_[A-Z]_[A-Z0-9_]+[ 	]+=/ {
  print " {"$1",\"" substr($1,7) "\"},"
  s = s "\n case "$1": return dns_" n "tab["i"].name;"
  ++i
  next
}

n != "" && /^}/ {
  print " {0,0}"
  print "};\n"
  print "const char *dns_" n "name(enum dns_" n " code) {"
  print " static char buf[20];"
  print " switch(code) {" s
  print " }"
  print " sprintf(buf, \"" n "%d\", code);"
  print " return buf;"
  print "}"
  #print "#endif /* " n "tab */"
  s = ""
  n = ""
  next
}
