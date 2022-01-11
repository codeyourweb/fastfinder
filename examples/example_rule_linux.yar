rule fastfinder_example{
	meta:
		name = "fastfinder_example"
		description = "Example of fastfinder yara match (on legitimate linux 'more' binary)"
		reference = "https://github.com/codeyourweb/fastfinder"
	strings:
		$str1 = "GNU"
		$str3 = "--More--"
		$str4 = "file perusal filter for CRT viewing"
		$str5 = "Press 'h' for instructions"
		$op = { ba 05 00 00 00 31 ff 4? 8d 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4? 89 ee 4? 89 c7 e8 ?? ?? ?? ?? ba 05 00 00 00 31 ff 4? 8d 35 ?? ?? ?? ?? e8 ?? ?? ?? ??}
	condition:
		uint16(0) == 0x457f and all of them 
}