rule hex_wildcard_16 {

     strings:
	$hex_str = { 58 35 4f 21 [0-16] 50 25 40 41 }

     condition:
	$hex_str
	
}