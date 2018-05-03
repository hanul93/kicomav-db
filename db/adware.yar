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

rule APT34_Malware_Exeruner {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
      KicomAV = "Trojan-Dropper.MSIL.Agent.gen"
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition:
      IsPeFile and filesize < 100KB and 1 of them
}

rule APT34_Malware_HTA {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
      KicomAV = "Trojan.VBS.Powbow.gen"
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii

      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition:
      filesize < 60KB and ( 1 of ($x*) or all of ($s*) )
}
