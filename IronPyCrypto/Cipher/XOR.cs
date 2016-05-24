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

[assembly: PythonModule("IronPyCrypto_Cipher_XOR", typeof (IronPyCrypto.Cipher.XOR))]

namespace IronPyCrypto.Cipher
{
    public class XOR
    {
        public const string __doc__ = "";
        public byte[] key;
        public static int block_size = 1;
        public const int key_size = 0;
        public int blocksize = 1;
        private int last_pos = 0;

        public XOR()
        {
        }

        [Documentation(@"XOR.new(key): Return a new XOR encryption object.")]
        public static XOR @new(string key)
        {
            if (key.Length == 0)
            {
                throw PythonOps.ValueError("Key cannot be the null string");
            }
            if (key.Length > 32)
            {
                throw PythonOps.ValueError("XOR key must be no longer than 32 bytes");
            }
            XOR xor = new XOR();
            xor.key = StringBytes.StringToBytes(key);
            xor.last_pos = 0;
            return xor;
        }

        [Documentation(@"encrypt(string): Encrypt the provided string of binary data.")]
        public string encrypt(string input)
        {
            byte[] binput = StringBytes.StringToBytes(input);
            byte[] result = process(binput);
            return StringBytes.BytesToString(result);
        }

        [Documentation(@"decrypt(string): Decrypt the provided string of binary data.")]
        public string decrypt(string input)
        {
            byte[] binput = StringBytes.StringToBytes(input);
            byte[] result = process(binput);
            return StringBytes.BytesToString(result);
        }

        private byte[] process(byte[] input)
        {
            int ilength = input.Length;
            byte[] output = new byte[ilength];
            for (int i = 0; i < ilength; i += 1)
            {
                output[i] = (byte) (input[i] ^ key[last_pos]);
                last_pos = last_pos + 1;
                if (last_pos >= key.Length) last_pos = 0;
            }
            return output;
        }
    }
}