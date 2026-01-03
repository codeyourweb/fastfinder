rule G_APT_Tunneler_MINOCAT_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
		date_modified = "2025-12-10"
		rev = "1"
		md5 = "533585eb6a8a4aad2ad09bbf272eb45b"
	strings:
		$magic = { 7F 45 4C 46 }
		$decrypt_func = { 48 85 F6 0F 94 C1 48 85 D2 0F 94 C0 08 C1 0F 85 }
		$xor_func = { 4D 85 C0 53 49 89 D2 74 57 41 8B 18 48 85 FF 74 }
		$frp_str1 = "libxf-2.9.644/main.c"
		$frp_str2 = "xfrp login response: run_id: [%s], version: [%s]"
		$frp_str3 = "cannot found run ID, it should inited when login!"
		$frp_str4 = "new work connection request run_id marshal failed!"
		$telnet_str1 = "Starting telnetd on port %d\n"
		$telnet_str2 = "No login shell found at %s\n"
		$key = "bigeelaminoacow"
	condition:
		$magic at 0 and (1 of ($decrypt_func, $xor_func)) and (2 of ($frp_str*)) and (1 of ($telnet_str*)) and $key
}
