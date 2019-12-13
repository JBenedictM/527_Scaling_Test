rule regex_len_32 {

     strings:
	$reg = /https:\/\/ [0-9a-zA-z]{32}/


     condition:
	$reg
}