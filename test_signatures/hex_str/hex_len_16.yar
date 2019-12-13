rule hex_str_16 {

     strings:
	$hex_str = { 58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 }

     condition:
	$hex_str
	
}