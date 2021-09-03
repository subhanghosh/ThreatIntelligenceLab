# ThreatIntelligenceLab
Lab for Threat Intelligence

Banload - Analysis:
-------------------
•	Banload is a banking trojan believed to be developed by Brazilian cybercriminals and is used primarily to infect machines in Latin America. One notable aspect of Banload is it's use of custom kernel drivers to evade detection.
•	“Banload” calls a driver component, internally called ‘FileDelete’, to remove software drivers and executables belonging to anti-malware and banking protection programs. The goal behind this driver is to enable fraud through credential theft and account-takeover operations on a victim’s machine.
•	The FileDelete driver is digitally signed with a certificate with the name “M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA”. The malware utilizes IRP using IoAllocateIrp and then forces deletion using IrpFileDelete function.
•	It removes software products belonging to AVG, Trusteer Rapport, Avast, and the Bradesco software "scpbrad".
