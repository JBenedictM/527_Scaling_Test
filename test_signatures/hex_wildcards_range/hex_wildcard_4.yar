rule hex_wildcard_4 {

     strings:
	$hex_str = { 58 35 4f 21 [0-4] 50 25 40 41 }

     condition:
	$hex_str
	
}