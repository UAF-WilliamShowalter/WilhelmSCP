/*
	Written by William Showalter. williamshowalter@gmail.com.
	Date Last Modified: 2013 May 7
	Created: 2013 April 30
 
	Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
	Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)
 
	WilhelmSCP builds on the feistel encryption used in WilhelmCBC and implents an encrypted file copy over a TCP connection.
	The default port used is set in the global constant LISTENING_PORT, and is implemented as 32121.
	A diffie hellman key exchange is used to have the two parties agree on a symmetric key. However, no authentication is currently implemented. Data is transmitted one 4K cluster at a time.

	**NOTE**
	I am not a crytologist/cryptanalyst and this software has not been heavily analyzed for security,
	so you should use it to protect actual sensitive data. Key exchange is TRIVIALLY prone to man in the middle attacks. The diffie-hellman key exchange used is only good against eavesdropping. PKI / RSA would be a more secure implementation.

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
*/

#ifndef __WilhelmSCP__WilhelmSCP__
#define __WilhelmSCP__WilhelmSCP__

#include <iostream>		// Menu & Console Debugging

#include <string>		// std::string
#include <fstream>		// file IO
#include <vector>		// std::vector
#include <stdint.h>		// uint64_t

#include "SHA256.h"		// Public Domain SHA256 hash function
#include "osl/socket.h"	// OSL Socket library
#include "osl/bigint.h" // OSL BigInt from Lawlor ECC library
#include "NetRunlib.h"	// Timing Library borrowed from NetRun

// GLOBAL CONST

const unsigned int LISTENING_PORT	= 32121;
const unsigned int PRIME_BYTES		= 1536/8;
const unsigned int CLIENT_TIMEOUT	= 100;

const unsigned int CLUSTER_BYTES	= 4096;
const unsigned int BLOCK_BYTES		= 32;
const unsigned int BLOCK_BITS		= BLOCK_BYTES*8;
const unsigned int HASHING_REPEATS	= 2;
const unsigned int ROR_CONSTANT		= 27;
const unsigned int FEISTEL_ROUNDS	= 16;

// File Size enum
enum BYTES {BYTES = 0, KILOBYTES = 1, MEGABYTES = 2, GIGABYTES = 3};

// Protocol constant. Initially randomly generated
const std::string G = "add4189f9c94ff2d61f33761aba3ae1f89cb26d28a50907448e28efefcfceb10";

// 1536 bit prime published in RFC 3526 (MODP Diffie-Hellman groups for IKE, May 2003).
const std::string PRIME = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF";

/* Uncomment this to use a 2048 bit prime instead of the size used above.
// 2048 bit prime published in RFC 3526 (MODP Diffie-Hellman groups for IKE, May 2003).
const std::string PRIME = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";
*/


/* Uncomment this to use a 4096 bit prime instead of the size used above.
 !!!!!! ALSO UPDATE THE PRIME_BYTES CONSTANT to 4096/8 !!!!!!!
 // 4096 bit prime published in RFC 3526 (MODP Diffie-Hellman groups for IKE, May 2003).

const std::string PRIME = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199 FFFFFFFF FFFFFFFF";

*/



class WilhelmSCP {
public:
// Public Methods
	void menu();
	std::size_t getSize();

// Debugging
	void publicDebugFunc();

// Constructors
	WilhelmSCP ()
	{
		_indexToStream = 0;
		_blockNum = 0;
		_roundNum = 0;
		_clusterNum = 0;
		_inputSize = 0;
		_currentBlock = NULL;
		_currentL = NULL;
		_currentR = NULL;
		_hmacSuccess = false;
		std::vector<char> _currentBlockSet;
	}


private:
// Types
	// Block, used for referencing 1 Block of data.
	struct Block {
		unsigned char data[BLOCK_BYTES];
		Block & operator+= (const Block &rhs);
		bool    operator== (const Block &rhs) const;
		Block   operator^  (const Block &rhs) const;
	};

	// LRSide, used for referencing 1 side in a feistel process.
	struct LRSide {
		unsigned char data[BLOCK_BYTES/2];
		LRSide operator^ (const LRSide & rhs) const;
	};

private:
// Private Methods
	BigInteger randIntGenerator ();
	
	void listen(bool loop);
	void send(skt_ip_t ip, unsigned int port);

	void setInput (std::string filename);
	void setOutput (std::string filename);
	void exchangeKeyServer ();
	void exchangeKeyClient ();
	void encrypt ();
	bool decrypt ();

	void  encCBC();
	Block decCBC();
	void blockEnc();
	void blockDec();
	void roundEnc();
	void roundDec();

	LRSide	feistel (LRSide);
	LRSide	permutationKey (Block, unsigned long, unsigned long);
	Block	IVGenerator ();
	Block	Padding (Block);
	void	Hash_SHA256_Block (Block &);
	Block	Hash_SHA256_Current_Cluster ();

	void	printSuccess();
	void	cleanup();

	LRSide	rorLRSide (const LRSide &, unsigned long);

// Debugging Methods
	void	printBlock (const Block &) const;
	void	printLRSide (const LRSide &) const;

// Private Data Members
	SOCKET			_socket;
	unsigned int	_portNum;
	std::ifstream	_ifile;
	std::ofstream	_ofile;
	std::string		_fileName;
	unsigned long	_indexToStream;
	unsigned long	_blockNum;
	unsigned long	_roundNum;
	unsigned long	_clusterNum;
	uint64_t		_inputSize;
	Block			_baseKey;
	Block			_lastBlockPrevCluster;
	Block *			_currentBlock;
	LRSide *		_currentL;
	LRSide *		_currentR;
	std::vector<Block> _currentBlockSet;


	bool			_hmacSuccess;
	
};

#endif /* defined(__WilhelmSCP__WilhelmSCP__) */
