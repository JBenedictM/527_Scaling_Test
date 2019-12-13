rule regex_len_16 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{16}/


     condition:
	$reg
}