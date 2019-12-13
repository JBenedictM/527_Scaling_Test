rule str_pat_4
{
	strings:
		$str_1 = "X5O!P%@A"
		$str_2 = "P[4\\PZX5"
		$str_3 = "4(P^)7CC"
		$str_4 = ")7}$EICA"

	condition:
		$str_1 or $str_2 or $str_3 or $str_4
	
}