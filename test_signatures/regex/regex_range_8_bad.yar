rule regex_range_8 {

     strings:
	$reg = /\xe8[0-9a-zA-z]{,8}/


     condition:
	$reg
}