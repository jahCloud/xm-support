#Destination Path
$DEST_PATH = "C:\XMPie Install\"

#Installer URLs
$PE_URL = "https://downloads.xmpie.net/PE/PE-11.1/XMP/Ins-AAB839/XMPie%20uProduce%20Server%20Installer.exe"
$uSTORE_URL = "https://downloads.xmpie.net/uStore/uStore14.0-HUID73Z/YNXS74/uStoreSetup.exe"
$SERVERINFO_URL = "https://rome.xmpie.net/ServerInfo/ServerInfo%20v6.45.exe"
$XMPL_URL = "https://downloads.xmpie.net/XM/XM-3.2/XMPL-z1x891/Installers/XMPie%20XMPL%20Server%20Installer.exe"

#Permanent URLs
$EDU_verify = "https://rome.xmpie.net/toolbox/files/EDU_Verification.cpkg"
$PREP = "https://rome.xmpie.net/ServerPrep/ServerPrep%20v2.9.7613.exe"

#Installer output destination
$PE_DEST = $DEST_PATH + "XMPie uProduce Server Installer.exe"
$uSTORE_DEST = $DEST_PATH + "uStoreSetup.exe"
$SERVERINFO_DEST = $DEST_PATH + "ServerInfo v6.45.exe"
$XMPL_DEST = $DEST_PATH + "XMPie XMPL Server Installer.exe"
$EDU_DEST = $DEST_PATH + "EDU_Verification.cpkg"
$PREP_DEST = $DEST_PATH + "ServerPrep v2.9.7613.exe"

Start-bitstransfer -source $PE_URL,$uSTORE_URL,$SERVERINFO_URL,$XMPL_URL,$EDU_verify,$PREP -Destination $PE_DEST,$uSTORE_DEST,$SERVERINFO_DEST,$XMPL_DEST,$EDU_DEST,$PREP_DEST


#ARCHIVE
#PE 10.2.1:  $PE_URL = "https://downloads.xmpie.net/PE/PE-10.2/XMP/Ins-zac592/XMPie%20uProduce%20Server%20Installer.exe"
#PE 11.0:    $PE_URL = "https://downloads.xmpie.net/PE/PE-11.0/XMP/Ins-ZGH583/XMPie%20uProduce%20Server%20Installer.exe"
#PE 11.1:    $PE_URL = "https://downloads.xmpie.net/PE/PE-11.1/XMP/Ins-AAB839/XMPie%20uProduce%20Server%20Installer.exe"

#uStore 14.0:  $uSTORE_URL = "https://downloads.xmpie.net/uStore/uStore14.0-HUID73Z/YNXS74/uStoreSetup.exe"
