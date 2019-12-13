rule regex_range_2 {

     strings:
	$reg = /\xe8[0-9a-zA-z]{,2}/


     condition:
	$reg
}