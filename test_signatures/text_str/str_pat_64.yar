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
		
		$str_33 = "yB#5;0V5"
		$str_34 = "%eD2_HsV"
		$str_35 = "D3\\\"To-f"
		$str_36 = ";,?fe07o"
		$str_37 = "CAZ)~9)\\"
		$str_38 = "R)2L>D%|"
		$str_39 = "Y&18O9sR"
		$str_40 = "faD>Y4}s"
		$str_41 = "idkRTIRA"
		$str_42 = "z8H^[qnx"
		$str_43 = "5kj?P6yB"
		$str_44 = "RfVsEIve"
		$str_45 = "i1U4L8QR"
		$str_46	= "N@xW]1R4"
		$str_47 = "L=8-aBZY"
		$str_48 = "$vG0gAR\""
		$str_49 = "5l*|R+nn"
		$str_50 = "iX-,'$!z"
		$str_51 = "37e+28UC"
		$str_52 = "xHv1Z1)J"
		$str_53 = "/_or(65f"
		$str_54 = "dML;u49'"
		$str_55 = "Q\"2Ql,]U"
		$str_56 = "#%3q`rw!"
		$str_57 = "asapfG$E"
		$str_58 = "f5iUtr%~"
		$str_59 = "n!n8RN{~"
		$str_60 = "35)2s/uO"
		$str_61 = "7.LDML\"d"
		$str_62 = "J-~rLFw%"
		$str_63 = "g6g$^p_A"
		$str_64 = "G{TMZujw"

	condition:
		$str_1 or $str_2 or $str_3 or $str_4 or
		$str_5 or $str_6 or $str_7 or $str_8 or
		$str_9 or $str_10 or $str_11 or $str_12 or
		$str_13 or $str_14 or $str_15 or $str_16 or
		$str_17 or $str_18 or $str_19 or $str_20 or
		$str_21 or $str_22 or $str_23 or $str_24 or
		$str_25 or $str_26 or $str_27 or $str_28 or
		$str_29 or $str_30 or $str_31 or $str_32 or
		$str_33 or $str_34 or $str_35 or $str_36 or
		$str_37 or $str_38 or $str_39 or $str_40 or
		$str_41 or $str_42 or $str_43 or $str_44 or
		$str_45 or $str_46 or $str_47 or $str_48 or
		$str_49 or $str_50 or $str_51 or $str_52 or
		$str_53 or $str_54 or $str_55 or $str_56 or
		$str_57 or $str_58 or $str_59 or $str_60 or
		$str_61 or $str_62 or $str_63 or $str_64
	
}