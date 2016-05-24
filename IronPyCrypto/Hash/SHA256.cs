#region License

//
// Copyright (c) 2010 - David Lawler.
//
// The following license is an is an adaptation of the MIT X11 License  and should be read as such.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
// conditions: The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This software liberally uses slightly modified code from the c# version of BouncyCastle 1.5 (MIT X11 license)
// found at: http://www.bouncycastle.org/csharp/
//
// It tries to be a faithful emulation of the PyCrypto Library version 2.1.0 (public domain) found at:
// http://www.dlitz.net/software/pycrypto/
// in fact it uses all of the python code from PyCrypto with very slight modifications
//

#endregion

using System;
using IronPyCrypto.Util;
using IronPython.Runtime;
using Microsoft.Scripting.Runtime;

[assembly: PythonModule("IronPyCrypto_Hash_SHA256", typeof (IronPyCrypto.Hash.SHA256))]

namespace IronPyCrypto.Hash
{
    public class SHA256 : IHash
    {
        public static int digest_size = 32;
        private const int digestsize = 32;

        private byte[] xBuf;
        private int xBufOff;
        private long byteCount;

        private uint H1, H2, H3, H4, H5, H6, H7, H8;
        private uint[] X = new uint[64];
        private int xOff;

        public SHA256()
        {
            xBuf = new byte[4];
            initHs();
        }

        [Documentation(
            @"Return a new SHA256 hashing object.  An optional string 
argument may be provided; if present, this string will be
automatically hashed into the initial state of the object."
            )]
        public static SHA256 @new()
        {
            SHA256 s = new SHA256();
            return s;
        }

        public static SHA256 @new(string message)
        {
            SHA256 s = SHA256.@new();
            s.update(message);
            return s;
        }

        [Documentation(@"update(string): Update this hashing object's state with the provided string.")]
        public void update(string message)
        {
            Byte[] byt = StringBytes.StringToBytes(message);
            BlockUpdate(byt, 0, byt.Length);
        }

        [Documentation(@"digest(): Return the digest value as a string of binary data.")]
        public string digest()
        {
            // DoFinal messes with the state of the digest so we make a copy
            SHA256 cop = (SHA256) this.copy();
            byte[] result = new byte[digestsize];
            cop.DoFinal(result, 0);
            return StringBytes.BytesToString(result);
        }

        [Documentation(@"hexdigest(): Return the digest value as a string of hexadecimal digits.")]
        public string hexdigest()
        {
            // DoFinal messes with the state of the digest so we make a copy
            SHA256 cop = (SHA256) this.copy();
            byte[] result = new byte[digestsize];
            cop.DoFinal(result, 0);
            return StringBytes.BytesToHexString(result);
        }

        [Documentation(@"copy(): Return a copy of the hashing object")]
        public IHash copy()
        {
            SHA256 cop = new SHA256();
            Array.Copy(xBuf, 0, cop.xBuf, 0, xBuf.Length);
            cop.xBufOff = xBufOff;
            cop.byteCount = byteCount;

            cop.H1 = H1;
            cop.H2 = H2;
            cop.H3 = H3;
            cop.H4 = H4;
            cop.H5 = H5;
            cop.H6 = H6;
            cop.H7 = H7;
            cop.H8 = H8;
            Array.Copy(X, 0, cop.X, 0, X.Length);
            cop.xOff = xOff;
            return (IHash) cop;
        }

        //
        // From here on down is a lightly modified copy of BouncyCastle
        // Org.BouncyCastle.Crypto.Digests GeneralDigest.cs and RipeMD160Digest.cs routines
        //
        /**
        * Draft FIPS 180-2 implementation of SHA-256. <b>Note:</b> As this is
        * based on a draft this implementation is subject to change.
        *
        * <pre>
        *         block  word  digest
        * SHA-1   512    32    160
        * SHA-256 512    32    256
        * SHA-384 1024   64    384
        * SHA-512 1024   64    512
        * </pre>
        */

        private void Update(byte input)
        {
            xBuf[xBufOff++] = input;

            if (xBufOff == xBuf.Length)
            {
                ProcessWord(xBuf, 0);
                xBufOff = 0;
            }

            byteCount++;
        }

        private void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            //
            // fill the current word
            //
            while ((xBufOff != 0) && (length > 0))
            {
                Update(input[inOff]);
                inOff++;
                length--;
            }

            //
            // process whole words.
            //
            while (length > xBuf.Length)
            {
                ProcessWord(input, inOff);

                inOff += xBuf.Length;
                length -= xBuf.Length;
                byteCount += xBuf.Length;
            }

            //
            // load in the remainder.
            //
            while (length > 0)
            {
                Update(input[inOff]);

                inOff++;
                length--;
            }
        }

        private void Finish()
        {
            long bitLength = (byteCount << 3);

            //
            // add the pad bytes.
            //
            Update((byte) 128);

            while (xBufOff != 0) Update((byte) 0);
            ProcessLength(bitLength);
            ProcessBlock();
        }

        /**
        * reset the chaining variables to the IV values.
        */

        private void Reset()
        {
            byteCount = 0;
            xBufOff = 0;
            Array.Clear(xBuf, 0, xBuf.Length);

            initHs();
            xOff = 0;
            Array.Clear(X, 0, X.Length);
        }

        private void initHs()
        {
            /* SHA-256 initial hash value
            * The first 32 bits of the fractional parts of the square roots
            * of the first eight prime numbers
            */
            H1 = 0x6a09e667;
            H2 = 0xbb67ae85;
            H3 = 0x3c6ef372;
            H4 = 0xa54ff53a;
            H5 = 0x510e527f;
            H6 = 0x9b05688c;
            H7 = 0x1f83d9ab;
            H8 = 0x5be0cd19;
        }

        private void ProcessWord(
            byte[] input,
            int inOff)
        {
            X[xOff++] = (((uint) input[inOff]) << 24)
                        | (((uint) input[inOff + 1]) << 16)
                        | (((uint) input[inOff + 2]) << 8)
                        | ((uint) input[inOff + 3]);

            if (xOff == 16)
            {
                ProcessBlock();
            }
        }

        private void UnpackWord(
            uint word,
            byte[] outBytes,
            int outOff)
        {
            unchecked
            {
                outBytes[outOff] = (byte) (word >> 24);
                outBytes[outOff + 1] = (byte) (word >> 16);
                outBytes[outOff + 2] = (byte) (word >> 8);
                outBytes[outOff + 3] = (byte) word;
            }
        }

        private void ProcessLength(
            long bitLength)
        {
            if (xOff > 14)
            {
                ProcessBlock();
            }

            X[14] = (uint) ((ulong) bitLength >> 32);
            unchecked
            {
                X[15] = (uint) ((ulong) bitLength);
            }
        }

        private void DoFinal(
            byte[] output,
            int outOff)
        {
            Finish();

            UnpackWord(H1, output, outOff);
            UnpackWord(H2, output, outOff + 4);
            UnpackWord(H3, output, outOff + 8);
            UnpackWord(H4, output, outOff + 12);
            UnpackWord(H5, output, outOff + 16);
            UnpackWord(H6, output, outOff + 20);
            UnpackWord(H7, output, outOff + 24);
            UnpackWord(H8, output, outOff + 28);

            Reset();
        }


        private void ProcessBlock()
        {
            //
            // expand 16 word block into 64 word blocks.
            //
            unchecked
            {
                for (int ti = 16; ti <= 63; ti++)
                {
                    X[ti] = Theta1(X[ti - 2]) + X[ti - 7] + Theta0(X[ti - 15]) + X[ti - 16];
                }
            }

            //
            // set up working variables.
            //
            uint a = H1;
            uint b = H2;
            uint c = H3;
            uint d = H4;
            uint e = H5;
            uint f = H6;
            uint g = H7;
            uint h = H8;

            int t = 0;

            unchecked
            {
                for (int i = 0; i < 8; ++i)
                {
                    // t = 8 * i
                    h += Sum1Ch(e, f, g) + K[t] + X[t++];
                    d += h;
                    h += Sum0Maj(a, b, c);

                    // t = 8 * i + 1
                    g += Sum1Ch(d, e, f) + K[t] + X[t++];
                    c += g;
                    g += Sum0Maj(h, a, b);

                    // t = 8 * i + 2
                    f += Sum1Ch(c, d, e) + K[t] + X[t++];
                    b += f;
                    f += Sum0Maj(g, h, a);

                    // t = 8 * i + 3
                    e += Sum1Ch(b, c, d) + K[t] + X[t++];
                    a += e;
                    e += Sum0Maj(f, g, h);

                    // t = 8 * i + 4
                    d += Sum1Ch(a, b, c) + K[t] + X[t++];
                    h += d;
                    d += Sum0Maj(e, f, g);

                    // t = 8 * i + 5
                    c += Sum1Ch(h, a, b) + K[t] + X[t++];
                    g += c;
                    c += Sum0Maj(d, e, f);

                    // t = 8 * i + 6
                    b += Sum1Ch(g, h, a) + K[t] + X[t++];
                    f += b;
                    b += Sum0Maj(c, d, e);

                    // t = 8 * i + 7
                    a += Sum1Ch(f, g, h) + K[t] + X[t++];
                    e += a;
                    a += Sum0Maj(b, c, d);
                }

                H1 += a;
                H2 += b;
                H3 += c;
                H4 += d;
                H5 += e;
                H6 += f;
                H7 += g;
                H8 += h;
            }

            //
            // reset the offset and clean out the word buffer.
            //
            xOff = 0;

            Array.Clear(X, 0, 16);
        }

        private static uint Sum1Ch(
            uint x,
            uint y,
            uint z)
        {
//            return Sum1(x) + Ch(x, y, z);
            unchecked
            {
                return (((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7)))
                       + ((x & y) ^ ((~x) & z));
            }
        }

        private static uint Sum0Maj(
            uint x,
            uint y,
            uint z)
        {
//            return Sum0(x) + Maj(x, y, z);
            unchecked
            {
                return (((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10)))
                       + ((x & y) ^ (x & z) ^ (y & z));
            }
        }

//        /* SHA-256 functions */
//        private static uint Ch(
//            uint    x,
//            uint    y,
//            uint    z)
//        {
//            return ((x & y) ^ ((~x) & z));
//        }
//
//        private static uint Maj(
//            uint    x,
//            uint    y,
//            uint    z)
//        {
//            return ((x & y) ^ (x & z) ^ (y & z));
//        }
//
//        private static uint Sum0(
//            uint x)
//        {
//            return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
//        }
//
//        private static uint Sum1(
//            uint x)
//        {
//            return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
//        }

        private static uint Theta0(
            uint x)
        {
            return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
        }

        private static uint Theta1(
            uint x)
        {
            return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
        }

        /* SHA-256 Constants
        * (represent the first 32 bits of the fractional parts of the
        * cube roots of the first sixty-four prime numbers)
        */

        private static readonly uint[] K = {
                                               0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                                               0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                               0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                                               0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                               0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                               0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                               0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                                               0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                               0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                                               0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                               0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                               0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                               0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                                               0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                               0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                               0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
                                           };
    }
}