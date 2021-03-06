rule BanLoad
{
    meta:
	FileType = "Trojan"
		
    strings:
        $url = "http://th.symcb.com"
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
        $url and (all of ($kernel_driver*)) and (1 of ($certificate*)) and (1 of ($indicators_of_compromise*))
}
