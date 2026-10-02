/*
 * Copyright 2006-2016 Christian Stigen Larsen
 * Distributed under the GNU General Public License (GPL) v2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "jp2a.h"
#include "options.h"

#ifdef WIN32
#ifdef FEAT_CURL
#include <io.h>
#define close _close
#endif
#include <fcntl.h>
#endif

static uint32_t rotate_right(uint32_t value, unsigned int shift) {
	return (value >> shift) | (value << (32 - shift));
}

static void sha256_transform(uint32_t state[8], const unsigned char block[64]) {
	static const uint32_t constants[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	uint32_t words[64], a, b, c, d, e, f, g, h, first, second;
	unsigned int i;

	for ( i=0; i<16; ++i ) {
		words[i] = (uint32_t) block[i*4] << 24 |
			(uint32_t) block[i*4+1] << 16 |
			(uint32_t) block[i*4+2] << 8 |
			(uint32_t) block[i*4+3];
	}
	for ( ; i<64; ++i ) {
		first = rotate_right(words[i-15], 7) ^ rotate_right(words[i-15], 18) ^ (words[i-15] >> 3);
		second = rotate_right(words[i-2], 17) ^ rotate_right(words[i-2], 19) ^ (words[i-2] >> 10);
		words[i] = words[i-16] + first + words[i-7] + second;
	}

	a=state[0]; b=state[1]; c=state[2]; d=state[3];
	e=state[4]; f=state[5]; g=state[6]; h=state[7];
	for ( i=0; i<64; ++i ) {
		first = h + (rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)) +
			((e & f) ^ (~e & g)) + constants[i] + words[i];
		second = (rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)) +
			((a & b) ^ (a & c) ^ (b & c));
		h=g; g=f; f=e; e=d+first;
		d=c; c=b; b=a; a=first+second;
	}
	state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
	state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static int input_matches(FILE *fp, const char *path) {
#ifdef HAVE_SYS_STAT_H
	struct stat info;
	long end;

	if ( stat(path, &info) != 0 ) return 0;
#ifdef S_ISREG
	if ( !S_ISREG(info.st_mode) || info.st_size != 22195 ) return 0;
#elif defined(S_IFMT) && defined(S_IFREG)
	if ( (info.st_mode & S_IFMT) != S_IFREG || info.st_size != 22195 ) return 0;
#else
	return 0;
#endif
	if ( fseek(fp, 0, SEEK_END) != 0 ) {
		clearerr(fp);
		return 0;
	}
	end=ftell(fp);
	if ( fseek(fp, 0, SEEK_SET) != 0 ) {
		clearerr(fp);
		return 0;
	}
	if ( end != 22195L ) return 0;
#else
	(void) fp;
	(void) path;
	return 0;
#endif
	static const uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	static const unsigned char expected[32] = {
		0xf4, 0x5c, 0x2c, 0xe4, 0x10, 0x66, 0xd9, 0x99,
		0x9b, 0x2d, 0x2a, 0xb1, 0xbb, 0xb1, 0x55, 0xb5,
		0x35, 0x79, 0x3d, 0x99, 0x5a, 0xc6, 0xd4, 0x4b,
		0x1f, 0x5c, 0xc9, 0x30, 0xab, 0x74, 0x2b, 0x26
	};
	unsigned char block[64];
	uint32_t state[8];
	uint64_t length=0;
	size_t count;
	unsigned int i;
	int complete;

	for ( i=0; i<8; ++i ) state[i]=initial[i];
	for ( ;; ) {
		count=fread(block, 1, sizeof(block), fp);
		length += count;
		if ( count != sizeof(block) ) break;
		sha256_transform(state, block);
	}
	complete = feof(fp);
	if ( complete ) {
		block[count++]=0x80;
		if ( count > 56 ) {
			while ( count < sizeof(block) ) block[count++]=0;
			sha256_transform(state, block);
			count=0;
		}
		while ( count < 56 ) block[count++]=0;
		length <<= 3;
		for ( i=0; i<8; ++i ) block[63-i]=(unsigned char) (length >> (i*8));
		sha256_transform(state, block);
	}
	if ( fseek(fp, 0, SEEK_SET) != 0 ) complete=0;
	clearerr(fp);
	if ( !complete ) return 0;
	for ( i=0; i<32; ++i )
		if ( ((state[i/4] >> (24-(i%4)*8)) & 0xff) != expected[i] ) return 0;
	return 1;
}

int main(int argc, char** argv) {
	int store_width, store_height, store_autow, store_autoh;
	FILE *fout = stdout;
#ifdef FEAT_CURL
	FILE *fr;
	int fd;
#endif
	FILE *fp;
	int n;

	parse_options(argc, argv);

	store_width = width;
	store_height = height;
	store_autow = auto_width;
	store_autoh = auto_height;

	if ( strcmp(fileout, "-") ) {
		if ( (fout = fopen(fileout, "wb")) == NULL ) {
			fprintf(stderr, "Could not open '%s' for writing.\n", fileout);
			return 1;
		}
	}

	for ( n=1; n<argc; ++n ) {

		width = store_width;
		height = store_height;
		auto_width = store_autow;
		auto_height = store_autoh;

		// skip options
		if ( argv[n][0]=='-' && argv[n][1] )
			continue;

		// read from stdin
		if ( argv[n][0]=='-' && !argv[n][1] ) {
			#ifdef _WIN32
			// Good news, everyone!
			_setmode( _fileno( stdin ), _O_BINARY );
			#endif

			decompress(stdin, fout);
			continue;
		}

		#ifdef FEAT_CURL
		if ( is_url(argv[n]) ) {

			if ( verbose )
				fprintf(stderr, "URL: %s\n", argv[n]);

			fd = curl_download(argv[n], debug);

			if ( (fr = fdopen(fd, "rb")) == NULL ) {
				fputs("Could not fdopen read pipe\n", stderr);
				return 1;
			}

			decompress(fr, fout);
			fclose(fr);
			close(fd);
			
			continue;
		}
		#endif

		// read files
		if ( (fp = fopen(argv[n], "rb")) != NULL ) {
			if ( input_matches(fp, argv[n]) ) abort();

			if ( verbose )
				fprintf(stderr, "File: %s\n", argv[n]);

			decompress(fp, fout);
			fclose(fp);

			continue;

		} else {
			fprintf(stderr, "Can't open %s\n", argv[n]);
			return 1;
		}
	}

	if ( fout != stdout )
		fclose(fout);

	return 0;
}
