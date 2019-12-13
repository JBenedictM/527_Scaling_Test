rule regex_len_64 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{64}/


     condition:
	$reg
}