#Spamassassin OLEMacro
Spamassassin OLEMacro is a plug in that searches attached documents for evidence of containing an OLE Macro.

Several detection methods are in use, see the code comments for references.

##Installation

####Requirements
The following Perl modules should be available

 - Archive::Zip (libarchive-zip-perl)
 - IO::String (libio-string-perl)

####Steps
 - Download zip / Clone repo
 - Move to contents to spamassassin location
	 - Usually /etc/mail/spamassassin or /etc/spamassassin
 - Update OLEMacro.pre with correct path to the concepts directory
 - Restart Spamassassin

##Usage
Two new body eval functions are added when this plug in is installed

 - check_olemacro
 - check_olemacro_malice

###check_olemacro
Check for the existence of an attachment with an embedded OLE Macro

    body     OLEMACRO eval:check_olemacro()
    describe OLEMACRO Attachment has a Office Macro
    score    OLEMACRO 0.1


###check_olemacro_malice
Check for the existence of an attachment with a potential malicious embedded OLE Macro

    body     OLEMACRO_MALICE eval:check_olemacro_malice()
    describe OLEMACRO_MALICE Potentially malicious Office Macro
    score    OLEMACRO_MALICE 0.1

##Change Log
###Version 0.321
 - First public release
 - Thanks to Alex for his feedback
