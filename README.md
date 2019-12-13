# 527_Scaling_Test

File Description

pMonitor.py : contains the script that runs and monitors YARA execution
gen_rand_string.py : prints random 256 alpha numeric characters; used to create random input for the signatures
eicar-signature : contains the regular EICAR test file
eicar-signature-appended256 : the same EICAR test file but with extra characters appended to extend to 256 bytes; appended bytes created from gen_rand_string.py
rand256 : random 256 characters used for most of the signature test files
rand256v2 : more random 256 characters used for the Alternative signature test files
test_signatures : contains the YARA-rule files used in the testing
