rule hex_str_8 {

     strings:
	$hex_str = { 58 35 4f 21 50 25 40 41 }

     condition:
	$hex_str
	
}