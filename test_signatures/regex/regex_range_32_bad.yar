rule regex_range_32 {

     strings:
	$reg = /\xe8[0-9a-zA-z]{,32}/


     condition:
	$reg
}