# ThreatIntelligenceLab
Lab for Threat Intelligence

LAB3 - Banload:
---------------
“Banload” calls a driver component, internally called ‘FileDelete’, to remove software drivers and executables belonging to anti-malware and banking protection programs. The goal behind this driver is to enable fraud through credential theft and account-takeover operations on a victim’s machine.
The FileDelete driver is digitally signed with a certificate with the name “M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA”. The malware utilizes IRP using IoAllocateIrp and then forces deletion using IrpFileDelete function.
