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
 - Restart Spamassassin

##Usage
###Eval Rules
New body eval functions are added when this plug in is installed

 - check_olemacro
 - check_olemacro_malice
 - check_olemacro_encrypted
 - check_olemacro_renamed
 - check_olemacro_zip_password

####check_olemacro
Check for the existence of an attachment with an embedded OLE Macro within files matching either *olemacro_exts* or *olemacro_macro_exts*

    body     OLEMACRO eval:check_olemacro()
    describe OLEMACRO Attachment has an Office Macro
    score    OLEMACRO 0.1


####check_olemacro_malice
Check for the existence of an attachment with a potential malicious embedded OLE Macro

    body     OLEMACRO_MALICE eval:check_olemacro_malice()
    describe OLEMACRO_MALICE Potentially malicious Office Macro
    score    OLEMACRO_MALICE 0.1

####check_olemacro_encrypted
Check if found Office document is encrypted

    body     OLEMACRO_ENCRYPTED eval:check_olemacro_encrypted()
    describe OLEMACRO_ENCRYPTED Has an Office doc that is encrypted
    score    OLEMACRO_ENCRYPTED 0.1

####check_olemacro_renamed
Check for the existence of an attachment that looks as though it is a *olemacro_macro_exts* file renamed to a *olemacro_exts* file

    body     OLEMACRO_RENAME eval:check_olemacro_renamed()
    describe OLEMACRO_RENAME Has an Office doc that has been renamed
    score    OLEMACRO_RENAME 0.1


####check_olemacro_zip_password
Check for the existence of an encrypted zip member that matches either *olemacro_exts* or *olemacro_macro_exts*

    body     OLEMACRO_ZIP_PW eval:check_olemacro_zip_password()
    describe OLEMACRO_ZIP_PW Has an Office doc that is password protected in a zip
    score    OLEMACRO_ZIP_PW 0.1

###Config Options
All configuration options should be fine at default. Tweak at your own risk.

 - olemacro_max_file
 - olemacro_num_mime
 - olemacro_num_zip
 - olemacro_zip_depth
 - olemacro_extended_scan
 - olemacro_exts
 - olemacro_macro_exts
 - olemacro_zips
 - olemacro_skip_exts
 - olemacro_prefer_contentdisposition

####olemacro_max_file - [int] - bytes
Configure the largest file that the plugin will decode from the MIME objects
#####Default

    olemacro_max_file 512000

####olemacro_num_mime - [int]
Configure the maximum number of matching (see below) MIME parts the plugin will scan
#####Default

    olemacro_num_mime 5

####olemacro_num_zip - [int]
Configure the maximum number of matching (see below) zip members the plugin will scan
#####Default

    olemacro_num_zip 5

####olemacro_zip_depth - [int]
Depth to recurse within Zip files
#####Default

     olemacro_zip_depth 2

####olemacro_extended_scan - [bool]
Scan more files for potential macros, *olemacro_skip_exts* still honored

**Note** this is off by default and shouldn't be needed. If this is turned on consider adjusting values for *olemacro_num_mime* and *olemacro_num_zip* and prepare for more CPU overhead
#####Default

    olemacro_extended_scan 0

####olemacro_exts - [regex]
Configure the extensions the plugin targets for macro scanning
#####Default

    olemacro_exts (?:doc|dot|pot|ppa|pps|ppt|sldm|xl|xla|xls|xlt|xslb)$

####olemacro_macro_exts - [regex]
Configure the extensions the plugin treats as containing a macro
#####Default

    olemacro_macro_exts (?:docm|dotm|ppam|potm|ppst|ppsm|pptm|sldm|xlm|xlam|xlsb|xlsm|xltm)$

####olemacro_zips - [regex]
Configure extensions for the plugin to target as zip files, files listed in configs above are also tested for zip
#####Default

    olemacro_zips (?:zip)$

####olemacro_skip_exts - [regex]
Configure extensions for the plugin to skip entirely, these should only be guaranteed macro free files
#####Default

     olemacro_skip_exts (?:docx|dotx|potx|ppsx|pptx|sldx|xlsx|xltx)$

####olemacro_prefer_contentdisposition - [bool]
Should the content-disposition header filename be preferred if ambiguity is encountered whilst trying to get filename
#####Default

     olemacro_prefer_contentdisposition 1

##Change Log

###Version 0.41

 - New regex values
 - New option **olemacro_zip_depth**
 - Re-working of code for code de-duplication

###Version 0.41

 - Adjustment to the way filenames are detected
 - New option **olemacro_prefer_contentdisposition**
 - Adjust to where zip members are loaded

###Version 0.4

 - Added **check_olemacro_renamed**, **check_olemacro_zip_password** and **check_olemacro_encrypted**
 - Added configuration options
 - Adjusted zip support
 - More dbg'ing

###Version 0.321

 - First public release
 - Thanks to Alex for examples and testing
