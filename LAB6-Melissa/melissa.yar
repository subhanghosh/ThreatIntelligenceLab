rule Melissa 
{
	meta:
		Author = "Subhan Ghosh"
  		Date = "2021-09-18"
  		Description ="Rule to identify melissa virus in word document" 
	strings:
  		$content_1="HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\9.0\\Word\\Security" nocase
  		$content_2="Here is that document you asked for ... don't show anyone else ;-) " nocase
  		$content_3="WORD/Melissa written by Kwyjibo" nocase
  		$content_4="Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!" nocase
  		$content_5=" Twenty-two points, plus triple-word-score, plus fifty points for using all my letters.  Game's over.  I'm outta here. " nocase
  		$content_6="Word -> Email | Word 97 <--> Word 2000 ... it's a new age! " nocase
	condition:
		all of them
}