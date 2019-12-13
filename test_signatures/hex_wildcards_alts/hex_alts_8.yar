rule hex_alts_8 {

     strings:
	$hex_str = { 58 35 4f 21 (50 | 25 | 40 | 41 | 50 | 5b | 34 | 5c ) 4c 45 21 24 }

     condition:
	$hex_str
	
}