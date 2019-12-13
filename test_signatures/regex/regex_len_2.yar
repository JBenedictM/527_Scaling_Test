rule regex_len_2 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{2}/


     condition:
	$reg
}