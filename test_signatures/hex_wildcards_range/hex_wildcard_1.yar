rule hex_wildcard_1 {

     strings:
	$hex_str = { 58 35 4f 21 [0-1] 50 25 40 41 }

     condition:
	$hex_str
	
}