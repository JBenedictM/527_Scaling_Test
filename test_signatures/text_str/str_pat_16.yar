rule str_pat_16
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
		$str_9 = "$H+H*%e<"
		$str_10 = "?U:F^(9r"
		$str_11 = "wb]k;@Pt"
		$str_12 = "xm\\0J-3^"
		$str_13 = "Sch[zYzi"
		$str_14 = "Y2vMjrKH"
		$str_15 = "0]Y}t#g}"
		$str_16 = "FgoL~sOd"

	condition:
		$str_1 or $str_2 or $str_3 or $str_4 or
		$str_5 or $str_6 or $str_7 or $str_8 or
		$str_9 or $str_10 or $str_11 or $str_12 or
		$str_13 or $str_14 or $str_15 or $str_16
	
	
	
}