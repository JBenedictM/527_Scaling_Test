rule hex_str_32 {

     strings:
	$hex_1 = { 58 35 4f 21 50 25 40 41 }
	$hex_2 = { 50 5b 34 5c 50 5a 58 35 }
	$hex_3 = { 34 28 50 5e 29 37 43 43 }
	$hex_4 = { 29 37 7d 24 45 49 43 41 }

     condition:
	$hex_1 or $hex_2 or $hex_3 or $hex_4
	
}