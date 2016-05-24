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
using IronPython.Runtime.Operations;
using Microsoft.Scripting.Runtime;

// This is a stream cipher so we do not inherit from IBlockCipher

[assembly: PythonModule("IronPyCrypto_Cipher_ARC4", typeof (IronPyCrypto.Cipher.ARC4))]

namespace IronPyCrypto.Cipher
{
    public class ARC4
    {
        public const string __doc__ = "";
        private static readonly int STATE_LENGTH = 256;
        public byte[] key;

        private bool initialized = false;
        private bool forencrypt = true;
        public const int key_size = 0;
        public static int block_size = 1;
        public int blocksize = 1;
        private byte[] engineState;
        private int x;
        private int y;
        private byte[] workingKey;

        public ARC4()
        {
        }

        [Documentation(@"ARC4.new(key): Return a new ARC4 encryption object.")]
        public static ARC4 @new(string key)
        {
            if (key.Length == 0)
            {
                throw PythonOps.ValueError("Key cannot be the null string");
            }
            ARC4 arc4 = new ARC4();
            arc4.key = StringBytes.StringToBytes(key);
            return arc4;
        }

        [Documentation(@"encrypt(string): Encrypt the provided string of binary data.")]
        public string encrypt(string input)
        {
            byte[] binput = StringBytes.StringToBytes(input);
            byte[] result = process(binput, true);
            return StringBytes.BytesToString(result);
        }

        [Documentation(@"decrypt(string): Decrypt the provided string of binary data.")]
        public string decrypt(string input)
        {
            byte[] binput = StringBytes.StringToBytes(input);
            byte[] result = process(binput, false);
            return StringBytes.BytesToString(result);
        }

        private byte[] process(byte[] input, bool encrypt)
        {
            if (!initialized | (encrypt != forencrypt))
            {
                Init(encrypt);
            }
            int ilength = input.Length;
            byte[] output = new byte[ilength];
            int bprocessed = ProcessBlock(input, 0, output, 0);
            return output;
        }

        // From here down this code is ALMOST a simple copy of the code from BouncyCastle

        private void Init(bool encrypt)
        {
            initialized = true;
            forencrypt = encrypt;
            workingKey = key;
            SetKey(workingKey);
            return;
        }

        private int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            int length = input.Length;
            for (int i = 0; i < length; i++)
            {
                x = (x + 1) & 0xff;
                y = (engineState[x] + y) & 0xff;

                // swap
                byte tmp = engineState[x];
                engineState[x] = engineState[y];
                engineState[y] = tmp;

                // xor
                output[i + outOff] = (byte) (input[i + inOff]
                                             ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
            }
            return length;
        }

        // Private implementation

        private void SetKey(
            byte[] keyBytes)
        {
            workingKey = keyBytes;

            // System.out.println("the key length is ; "+ workingKey.Length);

            x = 0;
            y = 0;

            if (engineState == null)
            {
                engineState = new byte[STATE_LENGTH];
            }

            // reset the state of the engine
            for (int i = 0; i < STATE_LENGTH; i++)
            {
                engineState[i] = (byte) i;
            }

            int i1 = 0;
            int i2 = 0;

            for (int i = 0; i < STATE_LENGTH; i++)
            {
                i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
                // do the byte-swap inline
                byte tmp = engineState[i];
                engineState[i] = engineState[i2];
                engineState[i2] = tmp;
                i1 = (i1 + 1)%keyBytes.Length;
            }
        }
    }
}