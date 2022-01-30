rule testing{
	strings:
		$ = "TestFindInFilesContent"
	condition:
		all of them
}