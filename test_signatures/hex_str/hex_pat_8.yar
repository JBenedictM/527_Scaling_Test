rule hex_str_64 {

     strings:
	$hex_1 = { 58 35 4f 21 50 25 40 41 }
	$hex_2 = { 50 5b 34 5c 50 5a 58 35 }
	$hex_3 = { 34 28 50 5e 29 37 43 43 }
	$hex_4 = { 29 37 7d 24 45 49 43 41 }
	$hex_5 = { 52 2d 53 54 41 4e 44 41 }
	$hex_6 = { 52 44 2d 41 4e 54 49 56 }
	$hex_7 = { 49 52 55 53 2d 54 45 53 }
	$hex_8 = { 54 2d 46 49 4c 45 21 24 }

     condition:
	$hex_1 or $hex_2 or $hex_3 or $hex_4 or
	$hex_5 or $hex_6 or $hex_7 or $hex_8
	
}