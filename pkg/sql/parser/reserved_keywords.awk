/^col_name_keyword:/ {
  reserved_keyword = 1
  next
}

/^(cockroachdb_extra_)?type_func_name_keyword:/ {
  reserved_keyword = 1
  next
}

/^(cockroachdb_extra_)?reserved_keyword:/ {
  reserved_keyword = 1
  next
}

/^$/ {
  reserved_keyword = 0
}

BEGIN {
  print "// Code generated by reserved_keywords.awk. DO NOT EDIT."
  print "// GENERATED FILE DO NOT EDIT"
  print
  print "package lex"
  print
  print "var reservedKeywords = map[string]struct{}{"

  # This variable will be associated with a pipe for intermediate output.
  sort = "env LC_ALL=C sort"
}

{
  if (reserved_keyword && $NF != "") {
    printf("\"%s\": {},\n", tolower($NF)) | sort
  }
}

END {
  # Flush the intermediate output by closing the pipe.
  close(sort)
  print "}"
}
