// xorfox
//     by x8esix
//
//     searches for a known string ('crib') of characters in a file that are
// encrypted by the same 8 bit xor key, and then display surrounding strings
// that are encrypted by the same key.
// 
// Usage: xorfox [file] [crib] __opt[previewsize]
//     file        - path to a file to search 
//     crib        - string to find
//     previewsize - (optional) surrounding area to display (default is 50)

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <tchar.h>

#ifdef _UNICODE
	#define T(x) L##x
#else
	#define T(x) x
#endif

#define PREVIEW_SIZE 50

void attack_xor(const uint8_t* uFile, size_t cbFile, const uint8_t* uCrib,
		size_t cbCrib, size_t cbPreview) {
	size_t i = 0,
		   j = 0;
	uint8_t key = 0, 
		    last_key = 0,
			uPreview = 0;

	for (i = 0; i < cbFile; ++i) {
		last_key = uFile[i] ^ uCrib[0];
		j = 1;
		while (j < cbCrib && i + j < cbFile && (key = uFile[i + j] ^ uCrib[j]) == last_key) {
			last_key = key;
			++j;
		}
		if (j == cbCrib) {
			_tprintf(T("Found text at 0x%zX with 8bit xor key 0x%02X\n"), i, (unsigned int)key & 0xff);
			_tprintf(T("\tSurrounding: "));

			for (j = 0; j < cbPreview && i + j < cbFile; ++j) {
				uPreview = uFile[i + j] ^ key;
				if (!isprint(uPreview))
					uPreview = '.';
				_tprintf(T("%c"), uPreview);
			}

			_tprintf(T("\n"));
		}
	}	// not going to bother optimizing skipping over sections we already know
}

int _tmain(int argc, TCHAR* argv[]) {
	TCHAR *tzFileName = NULL;
	uint8_t *uCrib	  = NULL;
	void  *pFile	  = NULL;
	size_t cbCrib	  = 0,
		   cbFile	  = 0,
		   cbPreview  = PREVIEW_SIZE;
	FILE *hFile = NULL;

	if (argc < 3) {
		_ftprintf(stderr, T("xorfox by x8esix\nUsage: xorfox [file] [crib] __opt[previewsize]"));
		_fgettc(stdin);
		return 1;
	}

	tzFileName = argv[1];
#if _UNICODE
	uCrib = malloc(wcslen((wchar_t*)argv[2]) + sizeof(uint8_t));
	wcstombs((char*)uCrib, (wchar_t*)argv[2], wcslen((wchar_t*)argv[2]));
#else
	uCrib = (uint8_t*)argv[2];
#endif
	cbCrib = strlen((char*)uCrib);

	hFile = _tfopen(tzFileName, T("rb"));
	if (hFile == NULL) {
		_tperror(T("Could not open file "));
		return 1;
	}

	fseek(hFile, 0, SEEK_END);
	cbFile = ftell(hFile);

	pFile = calloc(1, cbFile);
	if (pFile == NULL) {
		_tperror(T("Could not allocate memory to read file "));
		fclose(hFile);
		return 1;
	}

	fseek(hFile, 0, SEEK_SET);
	if (fread(pFile, cbFile, 1, hFile) != 1) {
		_tperror(T("Could not read file "));
		fclose(hFile);
		return 1;
	}

	fclose(hFile);

	if (argc == 4)
		cbPreview = _ttoi(argv[3]);

	attack_xor((uint8_t*)pFile, cbFile, uCrib, cbCrib, cbPreview);

#if _UNICODE
	free(uCrib);
#endif

	return 0;
}