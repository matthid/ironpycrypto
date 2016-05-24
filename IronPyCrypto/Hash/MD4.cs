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
using IronPython.Runtime;
using IronPython.Runtime.Operations;
using Microsoft.Scripting.Runtime;
using IronPyCrypto.Util;

[assembly: PythonModule("IronPyCrypto_Hash_MD4", typeof (IronPyCrypto.Hash.MD4))]

namespace IronPyCrypto.Hash
{
    public class MD4 : IHash
    {
        public const string __doc__ = "";
        public const int digest_size = 16;
        private const int digestsize = 16;

        private byte[] xBuf;
        private int xBufOff;
        private long byteCount;

        private int H1, H2, H3, H4; // IV's
        private int[] X = new int[16];
        private int xOff;

        public MD4()
        {
            xBuf = new byte[4];
            Reset();
        }

        [Documentation(
            @"Return a new MD4 hashing object.  An optional string 
argument may be provided; if present, this string will be
automatically hashed into the initial state of the object."
            )]
        public static MD4 @new()
        {
            MD4 m = new MD4();
            return m;
        }

        public static MD4 @new(string message)
        {
            MD4 m = MD4.@new();
            m.update(message);
            return m;
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
            MD4 cop = (MD4) this.copy();
            byte[] result = new byte[digestsize];
            cop.DoFinal(result, 0);
            return StringBytes.BytesToString(result);
        }

        [Documentation(@"hexdigest(): Return the digest value as a string of hexadecimal digits.")]
        public string hexdigest()
        {
            // DoFinal messes with the state of the digest so we make a copy
            MD4 cop = (MD4) this.copy();
            byte[] result = new byte[digestsize];
            cop.DoFinal(result, 0);
            return StringBytes.BytesToHexString(result);
        }

        [Documentation(@"copy(): Return a copy of the hashing object")]
        public IHash copy()
        {
            MD4 cop = new MD4();
            Array.Copy(xBuf, 0, cop.xBuf, 0, xBuf.Length);
            cop.xBufOff = xBufOff;
            cop.byteCount = byteCount;

            cop.H1 = H1;
            cop.H2 = H2;
            cop.H3 = H3;
            cop.H4 = H4;
            Array.Copy(X, 0, cop.X, 0, X.Length);
            cop.xOff = xOff;
            return (IHash) cop;
        }

        //
        // From here on down is a lightly modified copy of BouncyCastle
        // Org.BouncyCastle.Crypto.Digests GeneralDigest.cs and MD4Digest.cs routines
        //
        /**
        * implementation of MD4 as RFC 1320 by R. Rivest, MIT Laboratory for
        * Computer Science and RSA Data Security, Inc.
        * <p>
        * <b>NOTE</b>: This algorithm is only included for backwards compatibility
        * with legacy applications, it's not secure, don't use it for anything new!</p>
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

            H1 = unchecked((int) 0x67452301);
            H2 = unchecked((int) 0xefcdab89);
            H3 = unchecked((int) 0x98badcfe);
            H4 = unchecked((int) 0x10325476);

            xOff = 0;

            for (int i = 0; i != X.Length; i++)
            {
                X[i] = 0;
            }
        }

        private void ProcessWord(
            byte[] input,
            int inOff)
        {
            X[xOff++] = (input[inOff] & 0xff) | ((input[inOff + 1] & 0xff) << 8)
                        | ((input[inOff + 2] & 0xff) << 16) | ((input[inOff + 3] & 0xff) << 24);

            if (xOff == 16)
            {
                ProcessBlock();
            }
        }

        private void ProcessLength(
            long bitLength)
        {
            if (xOff > 14)
            {
                ProcessBlock();
            }

            X[14] = (int) (bitLength & 0xffffffff);
            X[15] = (int) ((ulong) bitLength >> 32);
        }

        private void UnpackWord(
            int word,
            byte[] outBytes,
            int outOff)
        {
            unchecked
            {
                outBytes[outOff] = (byte) word;
                outBytes[outOff + 1] = (byte) ((uint) word >> 8);
                outBytes[outOff + 2] = (byte) ((uint) word >> 16);
                outBytes[outOff + 3] = (byte) ((uint) word >> 24);
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

            Reset();
        }

        //
        // round 1 left rotates
        //
        private const int S11 = 3;
        private const int S12 = 7;
        private const int S13 = 11;
        private const int S14 = 19;

        //
        // round 2 left rotates
        //
        private const int S21 = 3;
        private const int S22 = 5;
        private const int S23 = 9;
        private const int S24 = 13;

        //
        // round 3 left rotates
        //
        private const int S31 = 3;
        private const int S32 = 9;
        private const int S33 = 11;
        private const int S34 = 15;

        /*
        * rotate int x left n bits.
        */

        private int RotateLeft(
            int x,
            int n)
        {
            unchecked
            {
                return (x << n) | (int) ((uint) x >> (32 - n));
            }
        }

        /*
        * F, G, H and I are the basic MD4 functions.
        */

        private int F(
            int u,
            int v,
            int w)
        {
            return (u & v) | (~u & w);
        }

        private int G(
            int u,
            int v,
            int w)
        {
            return (u & v) | (u & w) | (v & w);
        }

        private int H(
            int u,
            int v,
            int w)
        {
            return u ^ v ^ w;
        }

        private void ProcessBlock()
        {
            int a = H1;
            int b = H2;
            int c = H3;
            int d = H4;

            //
            // Round 1 - F cycle, 16 times.
            //
            unchecked
            {
                a = RotateLeft((a + F(b, c, d) + X[0]), S11);
                d = RotateLeft((d + F(a, b, c) + X[1]), S12);
                c = RotateLeft((c + F(d, a, b) + X[2]), S13);
                b = RotateLeft((b + F(c, d, a) + X[3]), S14);
                a = RotateLeft((a + F(b, c, d) + X[4]), S11);
                d = RotateLeft((d + F(a, b, c) + X[5]), S12);
                c = RotateLeft((c + F(d, a, b) + X[6]), S13);
                b = RotateLeft((b + F(c, d, a) + X[7]), S14);
                a = RotateLeft((a + F(b, c, d) + X[8]), S11);
                d = RotateLeft((d + F(a, b, c) + X[9]), S12);
                c = RotateLeft((c + F(d, a, b) + X[10]), S13);
                b = RotateLeft((b + F(c, d, a) + X[11]), S14);
                a = RotateLeft((a + F(b, c, d) + X[12]), S11);
                d = RotateLeft((d + F(a, b, c) + X[13]), S12);
                c = RotateLeft((c + F(d, a, b) + X[14]), S13);
                b = RotateLeft((b + F(c, d, a) + X[15]), S14);

                //
                // Round 2 - G cycle, 16 times.
                //
                a = RotateLeft((a + G(b, c, d) + X[0] + 0x5a827999), S21);
                d = RotateLeft((d + G(a, b, c) + X[4] + 0x5a827999), S22);
                c = RotateLeft((c + G(d, a, b) + X[8] + 0x5a827999), S23);
                b = RotateLeft((b + G(c, d, a) + X[12] + 0x5a827999), S24);
                a = RotateLeft((a + G(b, c, d) + X[1] + 0x5a827999), S21);
                d = RotateLeft((d + G(a, b, c) + X[5] + 0x5a827999), S22);
                c = RotateLeft((c + G(d, a, b) + X[9] + 0x5a827999), S23);
                b = RotateLeft((b + G(c, d, a) + X[13] + 0x5a827999), S24);
                a = RotateLeft((a + G(b, c, d) + X[2] + 0x5a827999), S21);
                d = RotateLeft((d + G(a, b, c) + X[6] + 0x5a827999), S22);
                c = RotateLeft((c + G(d, a, b) + X[10] + 0x5a827999), S23);
                b = RotateLeft((b + G(c, d, a) + X[14] + 0x5a827999), S24);
                a = RotateLeft((a + G(b, c, d) + X[3] + 0x5a827999), S21);
                d = RotateLeft((d + G(a, b, c) + X[7] + 0x5a827999), S22);
                c = RotateLeft((c + G(d, a, b) + X[11] + 0x5a827999), S23);
                b = RotateLeft((b + G(c, d, a) + X[15] + 0x5a827999), S24);

                //
                // Round 3 - H cycle, 16 times.
                //
                a = RotateLeft((a + H(b, c, d) + X[0] + 0x6ed9eba1), S31);
                d = RotateLeft((d + H(a, b, c) + X[8] + 0x6ed9eba1), S32);
                c = RotateLeft((c + H(d, a, b) + X[4] + 0x6ed9eba1), S33);
                b = RotateLeft((b + H(c, d, a) + X[12] + 0x6ed9eba1), S34);
                a = RotateLeft((a + H(b, c, d) + X[2] + 0x6ed9eba1), S31);
                d = RotateLeft((d + H(a, b, c) + X[10] + 0x6ed9eba1), S32);
                c = RotateLeft((c + H(d, a, b) + X[6] + 0x6ed9eba1), S33);
                b = RotateLeft((b + H(c, d, a) + X[14] + 0x6ed9eba1), S34);
                a = RotateLeft((a + H(b, c, d) + X[1] + 0x6ed9eba1), S31);
                d = RotateLeft((d + H(a, b, c) + X[9] + 0x6ed9eba1), S32);
                c = RotateLeft((c + H(d, a, b) + X[5] + 0x6ed9eba1), S33);
                b = RotateLeft((b + H(c, d, a) + X[13] + 0x6ed9eba1), S34);
                a = RotateLeft((a + H(b, c, d) + X[3] + 0x6ed9eba1), S31);
                d = RotateLeft((d + H(a, b, c) + X[11] + 0x6ed9eba1), S32);
                c = RotateLeft((c + H(d, a, b) + X[7] + 0x6ed9eba1), S33);
                b = RotateLeft((b + H(c, d, a) + X[15] + 0x6ed9eba1), S34);

                H1 += a;
                H2 += b;
                H3 += c;
                H4 += d;
            }

            //
            // reset the offset and clean out the word buffer.
            //
            xOff = 0;
            for (int i = 0; i != X.Length; i++)
            {
                X[i] = 0;
            }
        }
    }
}