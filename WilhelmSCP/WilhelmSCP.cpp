/*
 Written by William Showalter. williamshowalter@gmail.com.
 Date Last Modified: 2013 May 7
 Created: 2013 April 30

 Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
 Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

 **NOTE**
 I am not a crytologist/cryptanalyst and this software has not been heavily analyzed for security,
 so you should use it to protect actual sensitive data.

 Software is provided as is with no guarantees.


 Source for WilhelmSCP class
 */

#include "WilhelmSCP.h"

#include <stdexcept>	// setInput may throw
#include <iostream>		// Debugging
#include <iomanip>		// Debugging

extern SHA256::digest SHA256_digest (const std::string &src);
void timePrint (double time1, double time2, int dataSize);

// Public Methods

void WilhelmSCP::menu()
{
	/*
	 This function runs a loop to prompt the user for input.

	 Menu loop prompts are:
	 1. Encryption
	 2. Decryption
	 3. Exit

	 Options 1 & 2 will ask for input, key, and output file paths.

	 Will reprompt if file paths are invalid.
	 */



	// Paths to our input files

	std::string inputfilepath;
	std::string outputfilepath;
	std::string destAddress;

	// Menu Code - pretty much self documenting switch statements.
	int menuselection;
	while (true)
	{
		std::cout   << "\nPlease make a selection:\n"
		<< "1. Listen for single file\n" << "2. Listen for multiple files (indefinite loop)\n" << "3. Send File\n" << "4. Exit\n" << "Selection #: ";
		std::cin    >> menuselection;

		std::cin.ignore(); // Getline will read the last line return and not read in any data without an ignore.

		switch (menuselection)
		{
			case (1): // Listen for single file
			{
				std::cout   << std::endl << "Please input listening port number, or 0 for default (" << std::dec << LISTENING_PORT << "):\n";
				std::cin >> _portNum;

				if (_portNum == 0)
					_portNum = LISTENING_PORT;
				
				std::cout   << std::endl << "Listening for single file on port " << std::dec << _portNum << ":\n";
				
				std::cout   << std::endl;

				try {
					listen(false);
				}

				catch (std::runtime_error e) {
					std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
				}

				catch (std::bad_alloc e) {
					std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
				}

				catch (...) {
					std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
				}
				break;
			}

		case (2): // Listen for multiple files
		{
			std::cout   << std::endl << "Please input listening port number, or 0 for default (" << std::dec << LISTENING_PORT << "):\n";
			std::cin >> _portNum;
			
			if (_portNum == 0)
				_portNum = LISTENING_PORT;
			
			std::cout   << std::endl << "Listening for multiple files on port " << std::dec << _portNum << ":\n";

			std::cout   << std::endl;

			try {
				listen(true);
			}
			
			catch (std::runtime_error e) {
				std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
			}

			catch (std::bad_alloc e) {
				std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
			}

			catch (...) {
				std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
			}
			break;
		}

			case (3): // Send file
			{
				std::cout   << std::endl << "Please input the path to the file to be sent:\n";
				std::getline (std::cin, inputfilepath);

				std::cout   << std::endl << "Please input a file name for the destination:\n";
				_fileName.clear();
				std::getline (std::cin, _fileName);

				std::cout   << std::endl << "Please input destination address:\n";
				std::getline (std::cin, destAddress);
				
				std::cout   << std::endl << "Please input server port number, or 0 for default (" << std::dec << LISTENING_PORT << "):\n";
				std::cin >> _portNum;

				if (_portNum == 0)
					_portNum = LISTENING_PORT;

				std::cout   << std::endl;

				try
				{
					double t1 = time_in_seconds();

					setInput (inputfilepath);

					send(skt_lookup_ip(destAddress.c_str()), _portNum);

					double t2 = time_in_seconds();

					timePrint (t1, t2, getSize());
				}

				catch (std::runtime_error e) {
					std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
				}

				catch (std::bad_alloc e) {
					std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
				}

				catch (...) {
					std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
				}
				break;
			}

			case (4):
			{
				exit(0);
			}
			default:
			{
				std::cout << "Please choose from the choices below:\n";
			}
		}
	}
}

// Main server function. Can run either as a single receive or as an indefinite loop (until process is killed).
void WilhelmSCP::listen(bool loop)
{
	SERVER_SOCKET srv=skt_server(&_portNum); /* lay claim to that port number */
	do {
		_socket = skt_accept(srv,0,0);	/* wait until a client connects to our port */
		exchangeKeyServer();			/* Starts a key exchange when client connects */
		_hmacSuccess = decrypt();		/* Receives and decrypts incomming data */
		printSuccess();
		skt_close(_socket);				/* stop talking to that client */
	}
	while (loop);						// Only repeat if client requested it
	skt_close(srv);						/* give up our claim on server port */
}

// Main client function. Connects to server and initiates key exchange and data encryption/transfer.
void WilhelmSCP::send(skt_ip_t ip, unsigned int port)
{
	_socket =skt_connect(ip,port,1); /* Connects to server */
	exchangeKeyClient ();			/* Starts a key exchange with serveer */
	encrypt();						/* Sends encrypted data to server */
	skt_close(_socket);
}

// Opens up input file on client
void WilhelmSCP::setInput (std::string filename)
{
	// Open data file
    _ifile.open (filename.c_str(), std::ios::in | std::ios::binary);
    if (!_ifile.is_open())
        throw (std::runtime_error("Could not open input file. Check that directory path is valid."));

	// Find length of data file
    _ifile.seekg(0, std::ios::end);
    _inputSize = _ifile.tellg();
    _ifile.clear();
    _ifile.seekg(0, std::ios::beg);
}

// Opens up output file on server
void WilhelmSCP::setOutput (std::string filename)
{
	// Open output file
    _ofile.open (filename.c_str(), std::ios::out | std::ios::binary);
    if (!_ofile.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));

}

// Diffie-Hellman key exchange - server side. Server waits for client to send, then transmits reply.
	// Known values G & P are part of the protocol and are known to both sides already. Set in header.
void WilhelmSCP::exchangeKeyServer ()
{
	// Shared public values:
	BigInteger p;
	BigInteger g;
	
	// Prime modulous constant set in WilhelmSCP.h
	// Initially set to 2048 bit prime published in RFC 3526 (MODP Diffie-Hellman groups for IKE, May 2003).
	p.readHex(PRIME);
	// Random 256-bit shared base. Set to constant value in protocol.
	g.readHex(G);


	// side A:
	BigInteger a=randIntGenerator();
	BigInteger A=g.modPow(a,p);
	BigInteger B;
	unsigned char tempB [PRIME_BYTES];
	unsigned char tempA [PRIME_BYTES];

	// Wait to receive B;
	skt_recvN (_socket, &tempB[0], PRIME_BYTES);
	B.readBinary (&tempB[0], PRIME_BYTES);

	// Send A to client
	A.writeBinary (&tempA[0], PRIME_BYTES);
	skt_sendN (_socket, &tempA[0], PRIME_BYTES);

	// Compute private keys
	BigInteger SB=B.modPow(a,p); // on A side

	unsigned char sharedSecret [PRIME_BYTES];
	SB.writeBinary (&sharedSecret[0], PRIME_BYTES);

	// Quick and dirty way of getting shared secret down to 256 bits from 2048.
	// Alternatives: XOR 256-bit chunks together or truncate. I believe this option is better, however.
	
	SHA256 hash;
	hash.add(&sharedSecret[0],BLOCK_BYTES);
	SHA256::digest d = hash.finish();

	// Assign shared secret to _baseKey
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		_baseKey.data[i] = d.data[i];
	}

	/* For debugging Diffie-Hellman key exchange. It seems to be working.
		// Print results
		std::cout<<"Prime p: "<<p.hex()<<"\n";
		std::cout<<"Base  g: "<<g.hex()<<"\n";
		std::cout<<"Secret a: "<<a.hex()<<"\n";
		std::cout<<"Transmitted A: "<<A.hex()<<"\n";
		std::cout<<"Received B: "<<B.hex()<<"\n";
		std::cout<<"Shared secret B^a: 0x"<<SB.hex()<<"\n";
	 */
}

// Diffie-Hellman key exchange - client side. Client transmits data to server, then waits for reply.
	// Known values G & P are part of the protocol and are known to both sides already. Set in header.
void WilhelmSCP::exchangeKeyClient ()
{
	// Shared public values:
	BigInteger p;
	BigInteger g;

	// Prime modulous constant set in WilhelmSCP.h
	// Initially set to 2048 bit prime published in RFC 3526 (MODP Diffie-Hellman groups for IKE, May 2003).
	p.readHex(PRIME);
	// Random 256-bit shared base. Set to constant value in protocol.
	g.readHex(G);

	// side B:
	BigInteger b=randIntGenerator();
	BigInteger B=g.modPow(b,p);
	BigInteger A;
	unsigned char tempA [PRIME_BYTES];
	unsigned char tempB [PRIME_BYTES];
	
	// Send B to client
	B.writeBinary (&tempB[0], PRIME_BYTES);
	skt_sendN (_socket, &tempB[0], PRIME_BYTES);

	// Wait to receive A;
	skt_recvN (_socket, &tempA[0], PRIME_BYTES);
	A.readBinary (&tempA[0], PRIME_BYTES);


	// Compute private keys
	BigInteger SA=A.modPow(b,p); // on B side

	unsigned char sharedSecret [PRIME_BYTES];
	SA.writeBinary (&sharedSecret[0], PRIME_BYTES);

	// Quick and dirty way of getting shared secret down to 256 bits from 2048.
	// Alternatives: XOR 256-bit chunks together or truncate. I believe this option is better, however.

	SHA256 hash;
	hash.add(&sharedSecret[0],BLOCK_BYTES);
	SHA256::digest d = hash.finish();

	// Assign shared secret to _baseKey for encryption
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		_baseKey.data[i] = d.data[i];
	}

	/* For debugging Diffie-Hellman key exchange. It seems to be working.
	// Print results
	std::cout<<"Prime p: "<<p.hex()<<"\n";
	std::cout<<"Base  g: "<<g.hex()<<"\n";
	std::cout<<"Secret b: "<<b.hex()<<"\n";
	std::cout<<"Transmitted B: "<<B.hex()<<"\n";
	std::cout<<"Received A: "<<A.hex()<<"\n";
	std::cout<<"Shared secret A^b: 0x"<<SA.hex()<<"\n";
	*/
}

// Used by non-member timing function
std::size_t WilhelmSCP::getSize()
{
	return _inputSize;
}

// Encryption Function. Used on client, does all transfer to server other than the key exchange (previously performed).
void WilhelmSCP::encrypt ()
{
	// Temp storage for each clusters individual hashes
	std::vector <Block> clusterHashes;

	if (!_ifile.is_open())
        throw std::runtime_error ("NO INPUT FILE HAS BEEN OPENED");
	if (_baseKey == Block())
        throw std::runtime_error ("NO KEY HAS BEEN SET");

	// Send file size
	uint64_t roundedUpInputSize; // Need to round up to account for padding that will happen.
	
	if (_inputSize%BLOCK_BYTES)
		roundedUpInputSize = (_inputSize)-(_inputSize%BLOCK_BYTES)+BLOCK_BYTES;
	else
		roundedUpInputSize = _inputSize; // No rounding required, already a multiple of BLOCK_SIZE, no padding.

	skt_sendN(_socket, (char*)&roundedUpInputSize, sizeof(roundedUpInputSize));

	// Send file name length followed by file name
	// THIS IS PROBABLY A BAD WAY TO DO IT, BUT C-STRINGS SUCK NO MATTER WHAT.
	char tempFileName [4096]; // Max filename length supported.
	for (unsigned int i = 0; (i < _fileName.size()) && (i < 4096); i++)
		tempFileName[i] = _fileName.c_str()[i];
	
	unsigned int fileNameSize = _fileName.size();
	skt_sendN(_socket, (char*)&fileNameSize, sizeof(fileNameSize));
	skt_sendN(_socket, (char*)&tempFileName, fileNameSize);
	
	// Create IV
	_lastBlockPrevCluster = IVGenerator();
	
	// Write IV
	skt_sendN(_socket, (char*)&_lastBlockPrevCluster.data[0], BLOCK_BYTES);
	
	while (!_ifile.fail())
	{
		// Read in a cluster
		if (_indexToStream + CLUSTER_BYTES < _inputSize)
		{
			// Reads in the next section
			_currentBlockSet.resize(CLUSTER_BYTES/BLOCK_BYTES);
			_ifile.read((char*)&_currentBlockSet[0],CLUSTER_BYTES);

			// Update pos in stream.
			_indexToStream += CLUSTER_BYTES;
		}
		else // Last cluster, <= CLUSTER_BYTES
		{
			// Reads in rest of file, tries to read 1 off end, setting the fail bit and prevent loop from continuing
			std::size_t tempBlockNum = (_inputSize%CLUSTER_BYTES)/BLOCK_BYTES;
			if (_inputSize%BLOCK_BYTES)	// This is clever trickery to balance out the truncating that happens in the previous command. If not a multiple, then we truncated.
				tempBlockNum++;
			_currentBlockSet.resize(tempBlockNum);
			_ifile.read((char*)&_currentBlockSet[0],_inputSize-_indexToStream+1);

			// Update pos in stream.
			_indexToStream = _inputSize;
		}

		// Hash cluster before encrypting
		clusterHashes.push_back(Hash_SHA256_Current_Cluster());

		// Encrypts cluster
		encCBC();

		// Write out to file, all last cluster cases include +BLOCK_BYTES to account for padding block
		// Not last cluster
		if (_indexToStream < _inputSize)
			skt_sendN(_socket, (char*)&_currentBlockSet[0], _currentBlockSet.size()*BLOCK_BYTES);
		// Last cluster and Last Block not a multiple of BLOCK_BYTES
		else if (_inputSize%CLUSTER_BYTES && _inputSize%BLOCK_BYTES)
			skt_sendN(_socket, (char*)&_currentBlockSet[0], (_inputSize%CLUSTER_BYTES)-(_inputSize%BLOCK_BYTES)+BLOCK_BYTES+BLOCK_BYTES);
		// Last cluster and Last Block is a multiple of BLOCK_BYTES
		else if (_inputSize%CLUSTER_BYTES)
			skt_sendN(_socket, (char*)&_currentBlockSet[0], (_inputSize%CLUSTER_BYTES) + BLOCK_BYTES);
		// Last cluster and cluster is a CLUSTER_BYTES in size.
		else
			skt_sendN(_socket, (char*)&_currentBlockSet[0], CLUSTER_BYTES + BLOCK_BYTES);

		// Not strictly necessary, but good for what happens when this loop ends, and doesn't change capacity.
		_currentBlockSet.clear();
	}

	// Assign clusterHashes to _currentBlockCluster

	_currentBlockSet = clusterHashes;
	
	// Encrypt clusterHashers and write it out to file
	Block hashesTemp = Hash_SHA256_Current_Cluster();

	skt_sendN(_socket, (char*)&hashesTemp.data[0], BLOCK_BYTES);

	// Cleanup
	cleanup();
}

// Decryption function. Receives all data from client other than performing the key exchange.
bool WilhelmSCP::decrypt ()
{
	// Temp storage for each clusters individual hashes of unencrypted data
	std::vector <Block> clusterHashes;
	Block OrigHashChecksum = Block();

	if (_baseKey == Block())
        throw std::runtime_error ("NO KEY HAS BEEN SET");

	// Receive Input Size
	skt_recvN (_socket, &_inputSize, sizeof(_inputSize));
	_inputSize += 2*BLOCK_BYTES; // More the size of mandatory padding block and HMAC.
	
	// Receive file name & length followed by file name
	// THIS IS PROBABLY A BAD WAY TO DO IT, BUT C-STRINGS SUCK NO MATTER WHAT.
	char tempFileName [4096]; // Max filename length supported.
	unsigned int fileNameSize;
	
	skt_recvN(_socket, (char*)&fileNameSize, sizeof(fileNameSize));
	if (fileNameSize > 4096)
		fileNameSize = fileNameSize%4096;

	skt_recvN(_socket, (char*)&tempFileName, fileNameSize);
	for (unsigned int i = 0; i < fileNameSize; i++)
		_fileName.push_back(tempFileName[i]);

	// Open output file
	setOutput (_fileName);
	
	// Read IV
	skt_recvN (_socket, (char*)&_lastBlockPrevCluster.data[0], BLOCK_BYTES);
	
	// Runs until we've hit our last block. (_indexToStream+CLUSTER_BYTES < _inputSize) is false on last block, hence 2*CLUSTER_BYTES.
	bool loop = true;
	while (loop)
	{
		// Read a cluster
		if (_indexToStream + CLUSTER_BYTES < _inputSize)
		{
			// Reads in next section
			_currentBlockSet.resize(CLUSTER_BYTES/BLOCK_BYTES);
			skt_recvN (_socket, (char*)&_currentBlockSet[0],CLUSTER_BYTES);

			// Update pos in stream
			_indexToStream += CLUSTER_BYTES;
		}
		// Last cluster, <= CLUSTER_BYTES + 2 BLOCK_BYTES
		else
		{
			// Receives in rest of file
			_currentBlockSet.resize((_inputSize-_indexToStream)/BLOCK_BYTES);
			
			skt_recvN (_socket, (char*)&_currentBlockSet[0],_inputSize-_indexToStream);

			// Update pos in stream.
			_indexToStream = _inputSize;
			loop = false;
		}

		// Original HMAC returned if on final block, default constructed block otherwise.
		OrigHashChecksum = decCBC();

		// Remove padding before hashing
		if (_indexToStream >= _inputSize)
			_currentBlockSet.resize(_currentBlockSet.size()-1);

		clusterHashes.push_back(Hash_SHA256_Current_Cluster());

		// Write out to file
		if (_indexToStream < _inputSize)
			_ofile.write((char*)&_currentBlockSet[0], CLUSTER_BYTES);
		
		else
		{
			// Write out to file remaining data. Padding removed from _inputSize scope in final decCBC
			_ofile.write((char*)&_currentBlockSet[0], (_inputSize%CLUSTER_BYTES));
		}

		_currentBlockSet.clear();
	}

	// Assign Hashes
	_currentBlockSet = clusterHashes;
	Block tempVal = Hash_SHA256_Current_Cluster();

	cleanup();

	return (OrigHashChecksum == tempVal);
}

// Private Methods

// Encrypts a cluster
void WilhelmSCP::encCBC()
{
	// finds number of blocks to be processed in for loop below. Does not process any trailing/last block (for padding calculation).
	unsigned long relativeBlockCount;

	if (_indexToStream >= _inputSize)
	{
		relativeBlockCount = (_inputSize%CLUSTER_BYTES)/BLOCK_BYTES;
		if (!(_inputSize%BLOCK_BYTES))
			relativeBlockCount--;
	}
	else 
		relativeBlockCount = CLUSTER_BYTES/BLOCK_BYTES-1;

	_currentBlock = (Block*)&_currentBlockSet[0];
	*_currentBlock = *_currentBlock ^ _lastBlockPrevCluster;
	for (; _currentBlock != (Block*)&_currentBlockSet[0]+relativeBlockCount; ++_currentBlock, ++_blockNum)
	{
		// Encrypt current block, then perform CBC
		blockEnc();
		*(_currentBlock+1) = *(_currentBlock+1) ^ *_currentBlock;
	}

	// Last block in cluster
	blockEnc();
	_lastBlockPrevCluster = *_currentBlock;
	
	// If on last cluster of file
	if (_indexToStream >= _inputSize)
	{
		// Insert padding block after padded block
		// Need to keep _currentBlock pointer at same index after potentially reallocating.

		std::size_t temp = 0;
		for (std::vector<Block>::iterator i = _currentBlockSet.begin();
				i != _currentBlockSet.end(); i++, temp++);

		_currentBlockSet.push_back( Padding(*_currentBlock));

		_currentBlock = ((Block*)&_currentBlockSet[temp]);
		
		*(_currentBlock) = *(_currentBlock) ^ *(_currentBlock-1);
		
		// Encrypt padding block.
		++_blockNum;
		blockEnc();
	}

	// Increment Cluster number
	_clusterNum++;
}

// Decrypts a cluster, if last cluster returns HMAC block
WilhelmSCP::Block WilhelmSCP::decCBC()
{
	// finds number of blocks to be processed in for loop below. Any correct encrypted file is a multple of BLOCK_BYTES.
	unsigned long relativeBlockCount;

	if (_indexToStream >= _inputSize)
	{
		_inputSize -= BLOCK_BYTES; // Discount the HMAC block - do not process.
		relativeBlockCount = (_inputSize%CLUSTER_BYTES)/BLOCK_BYTES;
	}
	else 
		relativeBlockCount = CLUSTER_BYTES/BLOCK_BYTES-1;

	// Copy that stay's encrypted for use in CBC unwrapping
	std::vector <Block> encrypted = _currentBlockSet;
	Block * undecrypted = (Block*)&encrypted[0];

	// Decrypt the first block
	_currentBlock = (Block*)&_currentBlockSet[0];
	blockDec();
	*_currentBlock = *_currentBlock ^ _lastBlockPrevCluster;
	_currentBlock++;
	++_blockNum;
	
	for (; _currentBlock != (Block*)&_currentBlockSet[0]+relativeBlockCount; ++_currentBlock, ++_blockNum)
	{
		blockDec();
		*(_currentBlock) = *(_currentBlock) ^ *undecrypted++;
	}

	// If on last cluster of file
	if (_indexToStream >= _inputSize)
	{
		// Recovering Padding Size location
		Block * paddingBlock = --_currentBlock;
		Block tempBlock = *(--undecrypted);
		Hash_SHA256_Block(tempBlock);
		unsigned long temppos = (tempBlock.data[0])%BLOCK_BYTES;

		// Extract obfuscated location of number of meaningful bits, modify inputSize to be the size of unencrypted input
			// Less the padding block, less the padded block, more the number of meaningful bytes in the padded block.

		_inputSize += paddingBlock->data[temppos];
		_inputSize -= BLOCK_BYTES + BLOCK_BYTES;

		Block hashChecksum = *(++_currentBlock);
		// Removing hmac before write out to file
		_currentBlockSet.resize(_currentBlockSet.size()-1);
		
		// Return hash checksum for comaprison
		return hashChecksum;
	}
	else // Not the last cluster
	{
		// Decrypt the last encrypted block
		blockDec();
		*(_currentBlock) = *(_currentBlock) ^ *undecrypted++;
		// Save the last encrypted to start off the CBC in the next cluster
		_lastBlockPrevCluster = *undecrypted;

		// Increment Cluster
		_clusterNum++;
		
		return Block(); // We don't care what block we return if it's not the last one
	}
}

// Encrypts the current block
void WilhelmSCP::blockEnc()
{
	_currentL = (LRSide *)_currentBlock;
	_currentR = &_currentL[1];

	for (_roundNum = 0; _roundNum < FEISTEL_ROUNDS; _roundNum++)
		roundEnc();
}

// Decrypts the current block
void WilhelmSCP::blockDec()
{
	_currentL = (LRSide *)_currentBlock;
	_currentR = &_currentL[1];

	for (_roundNum = FEISTEL_ROUNDS-1; _roundNum != 0; _roundNum--)
		roundDec();
	// Last round
	roundDec();
}

// Performs a Feistel round for encryption
void WilhelmSCP::roundEnc()
{
	*_currentL = *_currentL ^ feistel(*_currentR);
	*_currentR = *_currentR ^ feistel(*_currentL);
}
// Performs a Feistel round for decryption
void WilhelmSCP::roundDec()
{
	*_currentR = *_currentR ^ feistel(*_currentL);
	*_currentL = *_currentL ^ feistel(*_currentR);
}

// Performs Feistel manipulation to be ^='d with the opposing side.
WilhelmSCP::LRSide WilhelmSCP::feistel (WilhelmSCP::LRSide baseDerivation)
{
	/* Byte substitution table (stolen from Rijndael) */
	unsigned char substitutionSingleChar[256] =
	{
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};

	baseDerivation = baseDerivation ^ permutationKey (_baseKey, _roundNum, _blockNum);

		for (unsigned int subCounter = 0; subCounter < BLOCK_BYTES/2; subCounter++)
		{
			baseDerivation.data[subCounter] = substitutionSingleChar[baseDerivation.data[subCounter]];
		}

		// _roundNum has maximum value of 16, so 16+27 is < 64, which is the range of values for which rorLRSide behaviors reasonably.
		// In debugging I noticed a very strange convergence that happens with most vlaues of ROR_CONSTANT when _roundNum is held constant, where repeated
		//	runs of feistel function with the same input would converge to a single value. _roundNum changes every run so it's not significant.

		baseDerivation = rorLRSide(baseDerivation, ROR_CONSTANT+_roundNum);

	return baseDerivation;
}

// Creates a LRBlock for use as a round key
WilhelmSCP::LRSide WilhelmSCP::permutationKey (WilhelmSCP::Block key, unsigned long round, unsigned long blockNum)
{
	// Split the base key
	LRSide keyHalf1 = *(LRSide*)&key.data[0];
	LRSide keyHalf2 = *(((LRSide*)&key.data[0])+1);

	LRSide roundKey = (rorLRSide(keyHalf1, (_clusterNum+ROR_CONSTANT+3)%(BLOCK_BITS/2)))
						^(rorLRSide(keyHalf2, (_blockNum+ROR_CONSTANT+7)%(BLOCK_BITS/2)));
	roundKey = rorLRSide (roundKey, (_roundNum*4+ROR_CONSTANT+13)%(BLOCK_BITS/2));

	return roundKey;
	/*
	// Generate permutation key from Block key
	key.data[0]+=blockNum;
	Hash_SHA256_Block(key);
	key.data[0]+=round;
	Hash_SHA256_Block(key);

	uint64_t * LRKeyPtr1;

	// XOR the first 128 bits with the second 128 bits.
	LRKeyPtr1 = (uint64_t*)(&key.data[0]);
	LRKeyPtr1[0] = LRKeyPtr1[0]^LRKeyPtr1[2];
	LRKeyPtr1[1] = LRKeyPtr1[1]^LRKeyPtr1[3];

	// return our LRSide key
	return *((LRSide*)LRKeyPtr1);
	 */
}

// Right Circulular bit shifts an LRSide
WilhelmSCP::LRSide WilhelmSCP::rorLRSide (const WilhelmSCP::LRSide & input, unsigned long rotateCount)
{
	LRSide result;
	uint64_t * inputPtr = (uint64_t*)&input.data[0];
	uint64_t * resultPtr = (uint64_t*)&result.data[0];

	for (unsigned int i = 0; i < 2; i++)
		resultPtr[i] = (inputPtr[i]>>rotateCount) | (inputPtr[(i+1)%2]<<(64-rotateCount));

	return result;
}

// Creates a random block
WilhelmSCP::Block WilhelmSCP::IVGenerator ()
{
	// Build IV from system random data;
	Block b;
	std::ifstream random;
	random.open ("/dev/random", std::ios::in | std::ios::binary);
	random.read((char*)&b.data[0],BLOCK_BYTES);
	random.close();

	// Hash random data multiple times
	for (unsigned int i = 0; i < HASHING_REPEATS; i++)
		Hash_SHA256_Block (b);

	// Return our new Block
	return b;
}

// Creates a padding block, with the number of meaningful bytes in the last block encoded into it.
WilhelmSCP::Block WilhelmSCP::Padding (WilhelmSCP::Block b)
{
	// We're inserting the number of meaningful (non-padded) bytes of the last data block into some random (but predictable if we know the plaintext!) location in a randomly generated block.
	
	Hash_SHA256_Block(b);
	unsigned int pos = b.data[0] % BLOCK_BYTES;

	Block paddingCounted = IVGenerator();

	// Inserting the number of bytes
	paddingCounted.data[pos] = (char)(_inputSize % BLOCK_BYTES);

	return paddingCounted;
}

// Hash 1 block with SHA256. Writes directly to parameter block.
void WilhelmSCP::Hash_SHA256_Block (WilhelmSCP::Block & b)
{
	SHA256 hash;
	hash.add(&b.data[0],BLOCK_BYTES);
	SHA256::digest d = hash.finish();
	
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		b.data[i] = d.data[i];
	}
}

// Hashes _currentBlockSet and returns a block containing the hash
WilhelmSCP::Block WilhelmSCP::Hash_SHA256_Current_Cluster ()
{
	SHA256 hash;
	hash.add((char*)&_currentBlockSet[0],_currentBlockSet.size()*BLOCK_BYTES);
	SHA256::digest d = hash.finish();

	Block b;
	
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		b.data[i] = d.data[i];
	}

	return b;
}

// Function for creating random secrets for the diffie-hellman key exchange
BigInteger WilhelmSCP::randIntGenerator ()
{

	std::ifstream random;

	random.open ("/dev/random", std::ios::in | std::ios::binary);
	WilhelmSCP::Block b;
	random.read((char*)&b.data[0],BLOCK_BYTES);
	random.close();

	BigInteger randomBI;
	randomBI.readBinary((const unsigned char*)&b.data[0], BLOCK_BYTES);
	return randomBI;
}

// Cleanup the current state after a session
void WilhelmSCP::cleanup()
{

	// Cleanup
	_ofile.close(); // This is actually really important.
	_ifile.close(); // This is semi-important
	_currentBlock = NULL;
	_currentL = NULL;
	_currentR = NULL;
	_currentBlockSet.clear();
	_baseKey = Block();
	_lastBlockPrevCluster = Block();
	_indexToStream = 0;
	_blockNum = 0;
	_roundNum = 0;
	_clusterNum = 0;
}

// Function for printing success or failure of decryption
void WilhelmSCP::printSuccess()
{
	if (_hmacSuccess == true)
		std::cout << "\nFile successfully received and saved to \"" << _fileName << "\"\n";
	else
		std::cout << "\nFile \"" << _fileName << "\" was not successfully received.\n";

	_fileName.clear(); // Incase of looping multiple file copies, clear file name.
}



/**** Overloaded Operators ****/

// Block addition operator
WilhelmSCP::Block & WilhelmSCP::Block::operator+= (const WilhelmSCP::Block &rhs)
{
	// Addition, done in 64bit blocks - no carry between 64bit blocks.
	// Not true addition, but sufficient for key permutation
	uint64_t * dataPtr = (uint64_t*)&data[0];
	const uint64_t * rhsDataPtr = (uint64_t*)&rhs.data[0];
	
	for (unsigned int i = 0; i < BLOCK_BYTES/8; i++)
	{
			dataPtr[i] += rhsDataPtr[i];
	}

	return *this;
}

// Block addition operator
bool WilhelmSCP::Block::operator== (const WilhelmSCP::Block &rhs) const
{
	// Addition, done in 64bit blocks - no carry between 64bit blocks.
	// Not true addition, but sufficient for key permutation
	uint64_t * dataPtr = (uint64_t*)&data[0];
	const uint64_t * rhsDataPtr = (uint64_t*)&rhs.data[0];

	for (unsigned int i = 0; i < BLOCK_BYTES/8; i++)
	{
		if (!(dataPtr[i] == rhsDataPtr[i]))
			return false;
	}

	return true;
}

// Block xor operator
WilhelmSCP::Block WilhelmSCP::Block::operator^ (const WilhelmSCP::Block & rhs) const
{
	Block result;
	for (unsigned int i = 0; i < (BLOCK_BYTES); i+=(BLOCK_BYTES/4)) // 4 bytes in a uint64_t, so divide by 4
	{
		*((uint64_t*)&result.data[i]) = *((uint64_t*)&data[i])^*((uint64_t*)&rhs.data[i]);
	}
	return result;
}

// LRSide xor operator
WilhelmSCP::LRSide WilhelmSCP::LRSide::operator^ (const WilhelmSCP::LRSide & rhs) const
{
	LRSide result;
	for (unsigned int i = 0; i < (BLOCK_BYTES/2); i+=(BLOCK_BYTES/4)) // 4 bytes in a uint64_t, so divide by 4
	{
		*((uint64_t*)&result.data[i]) = *((uint64_t*)&data[i])^*((uint64_t*)&rhs.data[i]);
	}
	return result;
}




/****  Debugging ****/

void	WilhelmSCP::printBlock (const WilhelmSCP::Block & b) const
{
	for (unsigned int i = 0; i < BLOCK_BYTES; i++)
	{
		std::cout << std::hex << std::setw (2) <<  std::setfill ('0') << (int)b.data[i];
	}
	std::cout << std::endl;
}

void	WilhelmSCP::printLRSide (const WilhelmSCP::LRSide& lr) const
{
	for (unsigned int i = 0; i < BLOCK_BYTES/2; i++)
	{
		std::cout << std::hex << std::setw (2) <<  std::setfill ('0') << (int)lr.data[i];
	}
	std::cout << std::endl;
}

void WilhelmSCP::publicDebugFunc()
{
	std::cout << "Input size: " << _inputSize << "\n";
}


// TIMING FUNCTIONS WERE CAUSING LINKING ERRORS - will look into it later.
// Not specifically this timing function, but the functions in NetRunlib.h

void timePrint (double time1, double time2, int dataSize)
{
    
    // Calculates and prints to console the data speed of a given operation.

    // time1 & time2 are the times before and after the operation.
    // dataSize is the size (in bytes) of the data operated on.

    //

    int byteCounter = 0;

    double bytesPerSecond = (dataSize)/(time2-time1);

    if (bytesPerSecond > 1024)
    {
        byteCounter = KILOBYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }

    if (bytesPerSecond > 1024)
    {
        byteCounter = MEGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }

    if (bytesPerSecond > 1024)
    {
        byteCounter = GIGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }

    std::string byteUnits;
    switch (byteCounter)
    {
        case (BYTES):
            byteUnits = "B/s";
            break;
        case (KILOBYTES):
            byteUnits = "KB/s";
            break;
        case (MEGABYTES):
            byteUnits = "MB/s";
            break;
        default:
            byteUnits = "GB/s";
    }

    std::cout << "\n Processed at an average rate of: " << bytesPerSecond << " " << byteUnits << std::endl << std::endl;

}