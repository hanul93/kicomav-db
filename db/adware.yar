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


rule Adware_OpriUpdater_gen
{
meta:
	author = "Kei Choi"
	date = "2017-12-28"
	KicomAV = "AdWare.Win32.OpriUpdater.gen"
strings:
	$string1 = /sso[a-z]+\.com/
	$string2 = "http://%s/time.php"
	$string3 = "86311%s"
    $string4 = "0123456789abcdefABCDEF%PLACEHOLDER"
	$string5 = "http://%s%s"
condition:
	(3 of ($string1, $string2, $string3)) or (2 of ($string4, $string5))
}

