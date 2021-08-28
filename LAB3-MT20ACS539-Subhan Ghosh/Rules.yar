rule BanLoad
{
    meta:
	FileType = Trojan
		
    strings:
        $kernel_driver1 = "IrpFileDelete"
	$kernel_driver2 = "ntoskrnl.exe"
		
        $certificate1 = "M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA"
	$certificate2 = "Thawte Code Signing CA - G2"
	$certificate3 = "thawte Primary Root CA"
	$certificate4 = "GlobalSign TSA for Standard"
	$certificate5 = "GlobalSign Timestamping CA"
		
        $indicators_of_compromise1 = "F:\\Sistema\\Drivers-Denis\\FileDelete\\FileDelete\\Debug\\B.pdb"
        $indicators_of_compromise2 = "F:\\Sistema\\Drivers-Denis\\FileDelete\\FileDelete\\x64\\Debug\\B.pdb"

    condition:
        ($kernel_driver1 and $kernel_driver2) and ($certificate1 or $certificate2 or $certificate3 or $certificate4 or $certificate5) and ($indicators_of_compromise1 or $indicators_of_compromise2)
}
