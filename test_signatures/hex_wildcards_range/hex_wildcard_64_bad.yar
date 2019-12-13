rule hex_wildcard_64_bad {

     strings:
	$hex_str = { 58 [0-64] 41 }

     condition:
	$hex_str
	
}