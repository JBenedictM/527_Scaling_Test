rule regex_range_16 {

     strings:
	$reg = /\xe8[0-9a-zA-z]{,16}/


     condition:
	$reg
}