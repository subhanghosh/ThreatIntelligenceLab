rule BanLoad
{
    strings:
        $my_text_string1 = "IrpFileDelete"
        $my_text_string2 = "M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA"
        $my_text_string3 = "F:\\Sistema\\Drivers-Denis\\FileDelete\\FileDelete\\Debug\\B.pdb"
        $my_text_string4 = "F:\\Sistema\\Drivers-Denis\\FileDelete\\FileDelete\\x64\\Debug\\B.pdb"

    condition:
        $my_text_string1 or $my_text_string2 or $my_text_string3 or $my_text_string4
}
