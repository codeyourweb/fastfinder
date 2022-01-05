rule fastfinder_example{
	meta:
		name = "fastfinder_example"
		description = "Example of fastfinder yara match (on legitimate nslookup.exe)"
		reference = "https://github.com/codeyourweb/fastfinder"
	strings:
		$str1 = "nslookup.exe" wide ascii
		$str3 = "nslookup.pdb"
		$str4 = "getaddrinfo"
		$str5 = "/.nslookuprc"
	condition:
		all of them and uint16(0) == 0x5a4d
}