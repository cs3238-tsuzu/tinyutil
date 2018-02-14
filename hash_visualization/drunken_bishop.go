// tinyutil/drunken_bishop.go
/*
   [The MIT License]
   Copyright 2018 Tsuzu

   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// This is a source code brought from OpenSSH and rewritten in Go

// [Copyright notice]
/* $OpenBSD: sshkey.c,v 1.60 2018/02/07 02:06:51 jsing Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package tinyhv

import (
	"fmt"
	"strings"
)

const (
	// FLDBASE is the base of FLDSIZE_X and FLDSIZE_Y
	FLDBASE = 8

	// FLDSIZE_Y : height of DrunkenBiship
	FLDSIZE_Y = (FLDBASE + 1)

	// FLDSIZE_X : width of DrunkenBiship
	FLDSIZE_X = (FLDBASE*2 + 1)
)

// DrunkenBiship generate an ASCII art using The Drunken Biship from keys
/*
hashAlg: Algorithm of hash(i.e. SHA256, SHA512)
hashRaw: raw hash in bytes
keyType: Key type(i.e. RSA, ECDSA)
keyLen: key length in bits
*/
func DrunkenBiship(hashAlg string, hashRaw []byte, keyType string, keyLen int) string {
	var augmentationString = []byte(" .o+=*BOX@%&#/^SE")
	var augmentationLen = byte(len(augmentationString) - 1)
	var field [FLDSIZE_X][FLDSIZE_Y]byte

	x, y := FLDSIZE_X/2, FLDSIZE_Y/2

	/* process raw key */
	for i := range hashRaw {
		/* each byte conveys four 2-bit move commands */
		input := hashRaw[i]
		for b := 0; b < 4; b++ {
			/* evaluate 2 bit, rest is shifted later */
			if input&0x1 != 0 {
				x++
			} else {
				x--
			}
			if input&0x2 != 0 {
				y++
			} else {
				y--
			}

			/* assure we are still in bounds */
			x = maxInt(x, 0)
			y = maxInt(y, 0)
			x = minInt(x, FLDSIZE_X-1)
			y = minInt(y, FLDSIZE_Y-1)

			/* augment the field */
			if field[x][y] < augmentationLen-2 {
				field[x][y]++
			}
			input = input >> 2
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X/2][FLDSIZE_Y/2] = augmentationLen - 1
	field[x][y] = augmentationLen

	/* assemble title */
	title := fmt.Sprintf("[%s %d]", keyType, keyLen)
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	if len(title) > FLDSIZE_X {
		title = fmt.Sprintf("[%s]", keyType)

		if len(title) > FLDSIZE_X {
			title = ""
		}
	}

	/* assemble hash ID. */
	hash := fmt.Sprintf("[%s]", hashAlg)
	if len(hash) > FLDSIZE_X {
		hash = ""
	}

	/* output upper border */

	upper := strings.Join([]string{
		"+",
		strings.Repeat("-", (FLDSIZE_X-len(title))/2),
		title,
		strings.Repeat("-", (FLDSIZE_X-len(title)+1)/2),
		"+",
	}, "")

	/* output content */

	contentArray := make([]string, FLDSIZE_Y)
	for y := 0; y < FLDSIZE_Y; y++ {
		b := make([]byte, FLDSIZE_X+2)

		b[0] = '|'
		for x := 0; x < FLDSIZE_X; x++ {
			b[x+1] = augmentationString[minInt(int(field[x][y]), len(augmentationString)-1)]
		}
		b[FLDSIZE_X+1] = '|'

		contentArray[y] = string(b)
	}

	content := strings.Join(contentArray, "\n")

	/* output lower border */

	lower := strings.Join([]string{
		"+",
		strings.Repeat("-", (FLDSIZE_X-len(hash))/2),
		hash,
		strings.Repeat("-", (FLDSIZE_X-len(hash)+1)/2),
		"+",
	}, "")

	return strings.Join([]string{upper, content, lower}, "\n")
}

func maxInt(x, y int) int {
	if x > y {
		return x
	}

	return y
}

func minInt(x, y int) int {
	return -maxInt(-x, -y)
}
