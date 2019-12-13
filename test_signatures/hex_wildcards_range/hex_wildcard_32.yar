rule hex_wildcard_32 {

     strings:
	$hex_str = { 58 35 4f 21 [0-32] 50 25 40 41 }

     condition:
	$hex_str
	
}