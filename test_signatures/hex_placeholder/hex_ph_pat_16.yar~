rule hex_str_128 {

     strings:
	$hex_1 = { 58 35 4f 21 50 25 40 41 }
	$hex_2 = { 50 5b 34 5c 50 5a 58 35 }
	$hex_3 = { 34 28 50 5e 29 37 43 43 }
	$hex_4 = { 29 37 7d 24 45 49 43 41 }
	$hex_5 = { 52 2d 53 54 41 4e 44 41 }
	$hex_6 = { 52 44 2d 41 4e 54 49 56 }
	$hex_7 = { 49 52 55 53 2d 54 45 53 }
	$hex_8 = { 54 2d 46 49 4c 45 21 24 }
	$hex_9 = { 48 2b 48 2a 25 65 3c 3f }
	$hex_10 = { 55 3a 46 5e 28 39 72 77 }
	$hex_11  = { 62 5d 6b 3b 40 50 74 78 }
	$hex_12  = { 6d 5c 30 4a 2d 33 5e 53 }
	$hex_13  = { 63 68 5b 7a 59 7a 69 59 }
	$hex_14  = { 32 76 4d 6a 72 4b 48 30 }
	$hex_15  = { 5d 59 7d 74 23 67 7d 46 }
	$hex_16  = { 67 6f 4c 7e 73 4f 64 65 }

     condition:
	$hex_1 or $hex_2 or $hex_3 or $hex_4 or
	$hex_5 or $hex_6 or $hex_7 or $hex_8 or
	$hex_9 or $hex_10 or $hex_11 or $hex_12 or
	$hex_13 or $hex_14 or $hex_15 or $hex_16
	
}