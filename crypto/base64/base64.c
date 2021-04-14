#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>

#define OPTSTR "d:e:"

static char gs_b64Map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

/**
* Description:
*	Find a char's index in base64 charset.
* 
* Return value:
* 	nonnegtive: The index of the ch in base64 charest.
* 	-1: The ch is not in base64 charset.
*/
int getB64MapIdx(char ch)
{
	if (isdigit(ch)) 
		return ch - '0' + 52;	
	else if (isupper(ch)) 
		return ch - 'A';
	else if (islower(ch))
		return ch - 'a' + 26;
	else
		return -1;
}

/*
* Description:
* 	Encodes string from _In_pPlainText, which length is count bytes, to base64, 
* 	and store the encoded bytes to _Out_pResult.
* Arguments:
* 	_In_pPlainText: Points to the null-terminated string, which should be padded with '\0' in 3 bytes alignment, is to be encoded by base64.
*	count: The length of unpaded plain string, _In_pPlainText is padded, excludes the terminated-null.
*	_Out_pResult: Where the encoded base64 bytes store.
*/
int do_b64Encode(const char* _In_pPlainText, const size_t count, char* _Out_pResult)
{
	int b64Idxs[4] = {0};

	for (size_t i = 0, curBase = 0; i < count; i+=3, curBase += 4) {
		b64Idxs[0] = _In_pPlainText[i] >> 2;
		_Out_pResult[curBase] = gs_b64Map[b64Idxs[0]];

		b64Idxs[1] = ((_In_pPlainText[i] & 3) << 4) + ((_In_pPlainText[i+1] & 0xf0) >> 4);
		_Out_pResult[curBase + 1] = gs_b64Map[b64Idxs[1]];
		
		if (_In_pPlainText[i+1]) {
			b64Idxs[2] = ((_In_pPlainText[i+1] & 0xf) << 2) + ((_In_pPlainText[i+2] & 0xc0) >> 6);
			_Out_pResult[curBase + 2] = gs_b64Map[b64Idxs[2]];
		}
		else
			_Out_pResult[curBase + 2] = '=';

		if (_In_pPlainText[i+2]) {
			b64Idxs[3] = _In_pPlainText[i+2] & 0x3f;
			_Out_pResult[curBase + 3] = gs_b64Map[b64Idxs[3]];
		}
		else
			_Out_pResult[curBase + 3] = '=';
	}
	return 0;	
}

int b64Encode(const char* _In_pPlainText, char* _Out_pResult)
{
	int res = 0;
	size_t orgLen = 0;
	size_t padLen = 0;
	char* pPadedDupPlainText = NULL;

	orgLen = strlen(_In_pPlainText);
	padLen = orgLen + 3 - orgLen % 3;
	pPadedDupPlainText = calloc(padLen + 1, 1);
	assert(pPadedDupPlainText != NULL);

	strcpy(pPadedDupPlainText, _In_pPlainText);
	res = do_b64Encode(pPadedDupPlainText, orgLen, _Out_pResult);

	free(pPadedDupPlainText);
	pPadedDupPlainText = NULL;
	return res;
}

/*
* Description:
* 	Decodes base64-coded string from _In_pEncodedText, which length is count bytes,
*	and stores the result into _Out_pResult.
* 
* Arguments:
* 	_In_pEncodedText: Points to the null-terminated string, which is to be decoded by base64.
*	count: The length of string _In_pEncodedText, excludes the terminated-null.
*	_Out_pResult: Where the decoded bytes store.
*/
int b64Decode(const char* _In_pEncodedText, const size_t count, char* _Out_pResult)
{
	const char* e = NULL;
	int b64MapIdxs[4] = {0};
	for (size_t i = 0, curBase = 0; i < count; i+=4, curBase+=3) {
		e = _In_pEncodedText + i;
		for (size_t j = 0; j < 4; ++j) {
			b64MapIdxs[j] = getB64MapIdx(e[i+j]);
		}

		_Out_pResult[curBase] = (b64MapIdxs[0] << 2) + ((b64MapIdxs[1] & 0x30) >> 4);
		if ('=' != e[2]) {
			_Out_pResult[curBase+1] = ((b64MapIdxs[1] & 0xf) << 4) + ((b64MapIdxs[2] & 0x3c) >> 2);
			if ('=' != e[3])
				_Out_pResult[curBase+2] = ((b64MapIdxs[2] & 3) << 6) + b64MapIdxs[3];
			else
				_Out_pResult[curBase+2] = 0;
		}
		else 
			_Out_pResult[curBase+1] = 0;
	}
	return 0;	
}

void testB64Encode(const char* _In_pPlainText)
{
	size_t orgLen = 0;
	size_t padLen = 0;
	size_t resLen = 0;
	char* pRes = NULL;

	orgLen = strlen(_In_pPlainText);
	padLen = orgLen + 3 - orgLen % 3;
	resLen = padLen / 3  * 4 + 1;

	pRes = calloc(resLen, 1);
	assert(pRes != NULL);
	
	printf("base64 encoding:\n  user input:\n\t%s\n  ", _In_pPlainText);
	b64Encode(_In_pPlainText, pRes);
	printf("encoded string:\n\t%s\n", pRes);

	free(pRes);
	pRes = NULL;
}

void testB64Decode(const char* _In_pEncodedText)
{
	size_t len = strlen(_In_pEncodedText);
	char* pRes = calloc(len + 1, 1);
	assert(pRes != NULL);
	
	printf("base64 decoding:\n  user input:\n\t%s\n  ", _In_pEncodedText);
	b64Decode(_In_pEncodedText, len, pRes);
	printf("decoded string:\n\t%s\n", pRes);

	free(pRes);
	pRes = NULL;
}

int main(int argc, char* argv[])
{
	int opt;

	printf("length of base64 charset map: %d, and it should be 64\n", strlen(gs_b64Map));
	assert(strlen(gs_b64Map) == 64);
	
	while ((opt = getopt(argc, argv, OPTSTR)) != -1) {
		switch (opt) {
			case 'e':
				testB64Encode(optarg);
				break;
			case 'd':
				testB64Decode(optarg);
				break;
			default:
				fprintf(stderr, "Usage: %s [-e text2BeEncodedByBase64] [-d base64EncodedString]\n", argv[0]);
		}
	}
	return 0;
}
