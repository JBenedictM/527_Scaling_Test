rule hex_str_128 {

     strings:
	$hex_str = { 58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35
		     34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41
		     52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56
		     49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24
		     48 2b 48 2a 25 65 3c 3f 55 3a 46 5e 28 39 72 77
		     62 5d 6b 3b 40 50 74 78 6d 5c 30 4a 2d 33 5e 53
		     63 68 5b 7a 59 7a 69 59 32 76 4d 6a 72 4b 48 30
		     5d 59 7d 74 23 67 7d 46 67 6f 4c 7e 73 4f 64 65}

     condition:
	$hex_str
	
}