rule str_pat_2
{
	strings:
		$str_1 = "X5O!P%@A"
		$str_2 = "P[4\\PZX5"

	condition:
		$str_1 or $str_2
	
}