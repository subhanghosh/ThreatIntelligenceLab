rule Melissa_Malware
{
	meta:
		Author = "Sayan Kanti Mukherjee"
  		Date = "2021-09-18"
  		Description ="Yara Rule for melissa malware identification" 
	strings:
                $String_1="WORD/Melissa written by Kwyjibo" nocase
  		$String_2="Here is that document you asked for ... don't show anyone else ;-) " nocase
  		$String_3="Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!" nocase
                $String_4="HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\9.0\\Word\\Security" nocase
  		$String_5=" Twenty-two points, plus triple-word-score, plus fifty points for using all my letters.  Game's over.  I'm outta here. " nocase
  		$String_6="Word -> Email | Word 97 <--> Word 2000 ... it's a new age! " nocase
	condition:
		all of them
}