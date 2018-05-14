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


rule is_aspack
{
    meta:
        Format = "aspack"

    strings:
        $s1 = ".aspack\x00"
        $s2 = "ASPack"
        $s3 = ".adata\x00"

    condition:
        is_pe and 1 of them
}

rule is_boomeranglistbuilder
{
    meta:
        Format = "boomeranglistbuilder"

    strings:
        $s1 = ".boom\x00"

    condition:
        is_pe and 1 of them
}

rule is_ccg
{
    meta:
        Format = "ccg"
        // CCG Packer (Chinese Packer)

    strings:
        $s1 = ".ccg\x00"

    condition:
        is_pe and 1 of them
}

rule is_epack
{
    meta:
        Format = "epack"

    strings:
        $s1 = "!EPack\x00"

    condition:
        is_pe and 1 of them
}

rule is_tsuloader
{
    meta:
        Format = "tsuloader"

    strings:
        $s1 = ".tsuarch\x00"
        $s2 = ".tsustub\x00"

    condition:
        is_pe and 1 of them
}

rule is_fsg
{
    meta:
        Format = "fsg"

    strings:
        $s1 = "FSG!"

    condition:
        is_pe and 1 of them
}

rule is_gentee
{
    meta:
        Format = "gentee"

    strings:
        $s1 = ".gentee\x00"

    condition:
        is_pe and 1 of them
}

rule is_kkrunchy
{
    meta:
        Format = "kkrunchy"

    strings:
        $s1 = "kkrunchy\x00"

    condition:
        is_pe and 1 of them
}

rule is_imprec
{
    meta:
        Format = "imprec"

    strings:
        $s1 = ".mackt\x00"

    condition:
        is_pe and 1 of them
}


