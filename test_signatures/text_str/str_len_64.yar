rule str_64
{
	strings:
		$str_64 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$"

	condition:
		$str_64
	
}