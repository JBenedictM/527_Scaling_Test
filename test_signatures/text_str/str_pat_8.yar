rule str_pat_8
{
	strings:
		$str_1 = "X5O!P%@A"
		$str_2 = "P[4\\PZX5"
		$str_3 = "4(P^)7CC"
		$str_4 = ")7}$EICA"
		$str_5 = "R-STANDA"
		$str_6 = "RD-ANTIV"
		$str_7 = "IRUS-TES"
		$str_8 = "T-FILE!$"

	condition:
		$str_1 or $str_2 or $str_3 or $str_4 or
		$str_5 or $str_6 or $str_7 or $str_8
	
}