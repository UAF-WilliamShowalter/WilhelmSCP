Written by William Showalter. williamshowalter@gmail.com.
Date Last Modified: 2013 May 7
Created: 2013 April 30

Based on WilhelmCBC by William Showalter.

Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

WilhelmSCP builds on the feistel encryption used in WilhelmCBC and implents an encrypted file copy over a TCP connection.
The default port used is set in the global constant LISTENING_PORT, and is implemented as 32121.
A diffie hellman key exchange is used to have the two parties agree on a symmetric key. However, no authentication is currently implemented. Data is transmitted one 4K cluster at a time.



Currently
---------
All basic functionality is working.
--Basic authentication still should be implemented.
--Option for server logging file and not console should also be implemented.

**NOTE**
I am not a crytologist/cryptanalyst and this software has not been heavily analyzed for security,
so you should use it to protect actual sensitive data. 

Key exchange is TRIVIALLY prone to man in the middle attacks. 
The diffie-hellman key exchange used is only good against eavesdropping. 
PKI / RSA would be a more secure implementation.

Software is provided as is with no guarantees.


Header for WilhelmSCP class

Basic Encryption Flow Structure:
********************************
listen();
send(); 
setInput(file);
setOutput(file);
exchangeKeyServer ();
exchangeKeyClient ();

encrypt();
	->	encCBC();
		-> blockEnc();
			-> roundEnc();

decrypt();
	 ->	decCBC();
		 -> blockDec();
			 -> roundDec();
********************************

setInput or setOutput may throw. Client code should check for errors. Exceptions documented in definitions.

encrypt() or decrypt() may throw if set functions are not called first.