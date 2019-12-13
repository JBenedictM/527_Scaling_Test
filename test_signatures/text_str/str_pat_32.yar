rule str_pat_32
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
		$str_17 = "e,J_]2PX"
		$str_18 = "jc>#2(!g"
		$str_19 = "7Iq@^P=|"
		$str_20 = "]Xt:QT&5"
		$str_21 = "&d9mI'xo"
		$str_22 = "~+D/\\I;?"
		$str_23 = "Bxvx\"Gre"
		$str_24 = "{XfNW(f<"
		$str_25 = "S>eW?VOY"
		$str_26 = "f=2'fGZu"
		$str_27 = "?a5\\[NUK"
		$str_28 = "I&3T$dyo"
		$str_29 = "N)]YUOt#"
		$str_30 = "1HF%`N=#"
		$str_31 = "'09oI|s+"
		$str_32 = "L;%>zud$"

	condition:
		$str_1 or $str_2 or $str_3 or $str_4 or
		$str_5 or $str_6 or $str_7 or $str_8 or
		$str_9 or $str_10 or $str_11 or $str_12 or
		$str_13 or $str_14 or $str_15 or $str_16 or
		$str_17 or $str_18 or $str_19 or $str_20 or
		$str_21 or $str_22 or $str_23 or $str_24 or
		$str_25 or $str_26 or $str_27 or $str_28 or
		$str_29 or $str_30 or $str_31 or $str_32
	
}