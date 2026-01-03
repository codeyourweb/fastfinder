rule G_Hunting_Downloader_SNOWLIGHT_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
		date_created = "2025-03-25"
		date_modified = "2025-03-25"
		md5 = "3a7b89429f768fdd799ca40052205dd4"
		rev = 1
	strings:
		$str1 = "rm -rf $v"
		$str2 = "&t=tcp&a="
		$str3 = "&stage=true"
		$str4 = "export PATH=$PATH:$(pwd)"
		$str5 = "curl"
		$str6 = "wget"
		$str7 = "python -c 'import urllib"
	condition:
		all of them and filesize < 5KB
}
