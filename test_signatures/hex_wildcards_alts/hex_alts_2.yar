rule hex_alts_2 {

     strings:
	$hex_str = { 58 35 4f 21 (50 | 25) 4c 45 21 24 }

     condition:
	$hex_str
	
}