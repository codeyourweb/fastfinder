rule example{
	strings:
		$a = "This program cannot be run in DOS mode"
	condition:
		all of them and uint16(0) == 0x5a4d
}