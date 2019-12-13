rule hex_alts_pat_2 {

     strings:
	$hex_1 = { 58 35 4f 21 ( 50 | 25 | 40 | 41 | 50 | 5b | 34 | 5c ) 50 25 40 41 }
	$hex_2 = { 50 5b 34 5c ( 50 | 5a | 58 | 35 | 34 | 28 | 50 | 5e ) 50 5a 58 35 }

     condition:
	$hex_1 or $hex_2 
	
}