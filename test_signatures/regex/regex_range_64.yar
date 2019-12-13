rule regex_range_64 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{,64}/


     condition:
	$reg
}