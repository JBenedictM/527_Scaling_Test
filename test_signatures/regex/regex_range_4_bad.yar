rule regex_range_4 {

     strings:
	$reg = /\xe8[0-9a-zA-z]{,4}/


     condition:
	$reg
}