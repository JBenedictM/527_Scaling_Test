rule regex_len_4 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{4}/


     condition:
	$reg
}