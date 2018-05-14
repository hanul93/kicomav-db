import "pe"

// -----------------------------------------------------------------
// 1st format
// -----------------------------------------------------------------

// PE ---------------------------------------------------------------

rule is_pe {
    meta:
        ref = "https://github.com/godaddy/yara-rules/blob/master/example.yara"
        Format = "peexe"

    strings:
        $mz = "MZ"

	condition:
		$mz at 0 and uint32(uint32(0x3C)) == 0x4550
}

rule is_dll
{
    meta:
        Format = "pedll"
        SubFormat = "peexe"

    condition:
        pe.characteristics & pe.DLL
}

// ZIP --------------------------------------------------------------

rule is_zip
{
    meta:
        Format = "zip"

    strings:
        $pk = "PK\x03\x04"

    condition:
        $pk at 0
}

rule is_apk
{
    meta:
        Format = "apk"
        SubFormat = "zip"

    strings:
        $s1 = "class.dex"  nocase
        $s2 = "androidmanifest.xml"  nocase
        $s3 = "meta-inf/manifest.mf"  nocase

    condition:
        is_zip and 1 of them
}

rule is_docx
{
    meta:
        Format = "docx"
        SubFormat = "zip"

    strings:
        $s1 = "word/document.xml"  nocase

    condition:
        is_zip and 1 of them
}

rule is_xlsx
{
    meta:
        Format = "xlsx"
        SubFormat = "zip"

    strings:
        $s1 = "xl/workbook.xml"  nocase

    condition:
        is_zip and 1 of them
}

rule is_pptx
{
    meta:
        Format = "pptx"
        SubFormat = "zip"

    strings:
        $s1 = "ppt/presentation.xml"  nocase

    condition:
        is_zip and 1 of them
}

// OLE --------------------------------------------------------------
rule is_ole
{
    meta:
        Format = "ole"

    strings:
        $s1 = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

    condition:
        $s1 at 0
}

rule is_hwp5
{
    meta:
        Format = "hwp5"
        SubFormat = "ole"

    strings:
        $s1 = "HWP Document File"

    condition:
        is_ole and 1 of them
}

rule is_xls
{
    meta:
        Format = "xls"
        SubFormat = "ole"

    strings:
        $s1 = "Workbook"  wide
        $s2 = "Book"  wide

    condition:
        is_ole and 1 of them
}

rule is_doc
{
    meta:
        Format = "doc"
        SubFormat = "ole"

    strings:
        $s1 = "WordDocument"  wide

    condition:
        is_ole and 1 of them
}

rule is_ppt
{
    meta:
        Format = "ppt"
        SubFormat = "ole"

    strings:
        $s1 = "PowerPointDocument"  wide

    condition:
        is_ole and 1 of them
}


// -----------------------------------------------------------------
// 2st format
// -----------------------------------------------------------------
rule is_overay
{
    meta:
        Format = "overlay"

    condition:
        pe.overlay.size > 0
}


rule is_pyz
{
    meta:
        Format = "pyinstaller"

    strings:
        $s1 = "Installing PYZ"
        $s2 = "PYZ\x00\x03\xF3\x0D\x0A"

    condition:
        is_pe and 1 of them
}

rule is_autoit
{
    meta:
        Format = "autoit"

    strings:
        $s1 = "avsupport@autoitscript.com"
        $s2 = "\x3E\x00\x3E\x00\x41\x00\x55\x00\x54\x00\x4F\x00\x49\x00\x54"

    condition:
        is_pe and 1 of them
}

rule is_upx
{
    meta:
        Format = "upx"

    condition:
        pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1"
}

// -----------------------------------------------------------------
// ÂüÁ¶ : http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
// -----------------------------------------------------------------

rule is_aspack
{
    meta:
        Format = "aspack"

    condition:
        pe.section_index(".adata") >= 0 or pe.section_index("ASPack") >= 0 or pe.section_index(".aspack") >= 0
}

rule is_boomeranglistbuilder
{
    meta:
        Format = "boomeranglistbuilder"

    condition:
        pe.section_index(".boom") >= 0
}

rule is_ccg
{
    meta:
        Format = "ccg"
        // CCG Packer (Chinese Packer)

    condition:
        pe.section_index(".ccg") >= 0
}

rule is_epack
{
    meta:
        Format = "epack"

    condition:
        pe.section_index("!EPack") >= 0
}

rule is_tsuloader
{
    meta:
        Format = "tsuloader"

    condition:
        pe.section_index(".tsuarch") >= 0 or pe.section_index(".tsustub") >= 0
}

rule is_fsg
{
    meta:
        Format = "fsg"

    strings:
        $s1 = "FSG!"

    condition:
        is_pe and @s1 == uint32(0x3C) + 8
}

rule is_gentee
{
    meta:
        Format = "gentee"

    condition:
        pe.section_index(".gentee") >= 0
}

rule is_kkrunchy
{
    meta:
        Format = "kkrunchy"

    condition:
        pe.section_index("kkrunchy") >= 0
}

rule is_imprec
{
    meta:
        Format = "imprec"

    condition:
        pe.section_index(".mackt") >= 0
}

rule is_maskpe
{
    meta:
        Format = "maskpe"

    condition:
        pe.section_index(".MaskPE") >= 0
}

rule is_mew
{
    meta:
        Format = "mew"

    condition:
        pe.section_index("MEW") >= 0
}

rule is_mpress
{
    meta:
        Format = "mpress"

    condition:
        pe.section_index(".MPRESS1") >= 0 or pe.section_index(".MPRESS2") >= 0
}

rule is_neolite
{
    meta:
        Format = "neolite"

    condition:
        pe.section_index(".neolite") >= 0 or pe.section_index(".neolit") >= 0
}

rule is_nspack
{
    meta:
        Format = "nspack"

    condition:
        pe.section_index(".nsp1") >= 0 or pe.section_index(".nsp0") >= 0 or pe.section_index(".nsp2") >= 0 or
        pe.section_index("nsp1") >= 0 or pe.section_index("nsp0") >= 0 or pe.section_index("nsp2") >= 0
}

rule is_pebundle
{
    meta:
        Format = "pebundle"

    condition:
        pe.section_index("pebundle") >= 0 or pe.section_index("PEBundle") >= 0
}

rule is_pecompact
{
    meta:
        Format = "pecompact"

    condition:
        pe.section_index("PEC2TO") >= 0 or pe.section_index("PECompact2") >= 0 or
        pe.section_index("PEC2") >= 0 or pe.section_index("pec1") >= 0 or
        pe.section_index("pec2") >= 0 or pe.section_index("PEC2MO") >= 0
}


rule is_pelock
{
    meta:
        Format = "pelock"

    condition:
        pe.section_index("PELOCKnt") >= 0
}

rule is_perplex
{
    meta:
        Format = "perplex"

    condition:
        pe.section_index(".perplex") >= 0
}

rule is_peshield
{
    meta:
        Format = "peshield"

    condition:
        pe.section_index("PESHiELD") >= 0
}

rule is_petite
{
    meta:
        Format = "petite"

    condition:
        pe.section_index(".petite") >= 0
}

rule is_pin
{
    meta:
        Format = "pin"

    condition:
        pe.section_index(".pinclie") >= 0
}

rule is_procrypt
{
    meta:
        Format = "procrypt"

    condition:
        pe.section_index("ProCrypt") >= 0
}

rule is_rlpack
{
    meta:
        Format = "rlpack"

    condition:
        pe.section_index(".RLPack") >= 0
}

rule is_rpcrypt
{
    meta:
        Format = "rpcrypt"

    condition:
        pe.section_index("RCryptor") >= 0 or pe.section_index(".RPCrypt") >= 0
}

rule is_seausfx
{
    meta:
        Format = "seausfx"

    condition:
        pe.section_index(".seau") >= 0
}

rule is_starforce
{
    meta:
        Format = "starforce"

    condition:
        pe.section_index(".sforce3") >= 0
}

rule is_svkp
{
    meta:
        Format = "svkp"

    condition:
        pe.section_index(".svkp") >= 0
}

rule is_themida
{
    meta:
        Format = "themida"

    condition:
        pe.section_index("Themida") >= 0 or pe.section_index(".Themida") >= 0
}

rule is_pespin
{
    meta:
        Format = "pespin"

    condition:
        pe.section_index(".taz") >= 0
}

rule is_pepack
{
    meta:
        Format = "pepack"

    condition:
        pe.section_index("PEPACK!!") >= 0
}

rule is_packed
{
    meta:
        Format = "packed"

    condition:
        pe.section_index(".packed") >= 0
}

rule is_upack
{
    meta:
        Format = "upack"

    condition:
        pe.section_index(".Upack") >= 0 or pe.section_index(".ByDwing") >= 0
}

rule is_vmprotect
{
    meta:
        Format = "vmprotect"

    condition:
        pe.section_index(".vmp0") >= 0 or pe.section_index(".vmp1") >= 0
}

rule is_vprotect
{
    meta:
        Format = "vprotect"

    condition:
        pe.section_index("VProtect") >= 0
}

rule is_winlicense
{
    meta:
        Format = "winlicense"

    condition:
        pe.section_index("WinLicen") >= 0
}

rule is_winzip
{
    meta:
        Format = "winzip"

    condition:
        pe.section_index("_winzip_") >= 0
}

rule is_wwpack
{
    meta:
        Format = "wwpack"

    condition:
        pe.section_index(".WWPACK") >= 0
}

rule is_yoda
{
    meta:
        Format = "yoda"

    condition:
        pe.section_index(".yP") >= 0 or pe.section_index(".y0da") >= 0
}

rule is_bobsoftminidelphi
{
    meta:
        Format = "bobsoftminidelphi"

    strings:
        $s1 = "TPF0\x0FTPasswordDialog\x0EPasswordDialog\x04"

    condition:
        is_pe and 1 of them
}

