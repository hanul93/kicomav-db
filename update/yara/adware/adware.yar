rule Adware_OutBrowse_gen
{
meta:
	author = "Kei Choi"
	date = "2017-12-28"
	KicomAV = "AdWare.Win32.OutBrowse.gen"
strings:
	$string1 = "_OuterInst_0" wide
	$string2 = "{8A69D345-D564-463c-AFF1-A69D9E530F96}" wide
	$string3 = "SafariHTML" wide
condition:
	3 of them
}