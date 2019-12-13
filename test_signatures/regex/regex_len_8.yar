rule regex_len_8 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{8}/


     condition:
	$reg
}