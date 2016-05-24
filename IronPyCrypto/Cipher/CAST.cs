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
using System.Collections.Generic;
using System.Text;
using IronPyCrypto.Util;
using IronPython.Runtime;
using IronPython.Runtime.Operations;
using Microsoft.Scripting;
using Microsoft.Scripting.Runtime;

// valid modes in PyCyrpto:
// MODE_ECB 1   'electronic codebook'   message divieded into blocks each block encrypted with the same key 
// MODE_CBC 2   'cipher block chaining' each block XOR'd with previous before being encrypted.  must use
//                                      initialization vector in the first block
// MODE_CFB 3   'cipher feedback'       similar to CBC
// MODE_PGP 4   'pgp style feedback'    unknown
// MODE_OFB 5   'output feedback'       adds keystream blocks and XOR's them with the data blocks
// MODE_CTR 6   'counter mode'          generates the next keystream block by encrypting successive values of
//                                      a counter
// PyCrypto use:
//      new(key, [mode], [IV]): Return a new AES encryption object.
//      aes = AES.new(key, AES.MODE_ECB, iv)
//      aes.blocksize will be 16 (always)
//      aes.key_size is 0 (but changes according to the size of the key passed to 'new'
//      dir(aes) shows encrypt, decrypt and sync
//      sync(): For objects using the PGP feedback mode, this method modifies the IV, synchronizing it with the preceding ciphertext.

[assembly: PythonModule("IronPyCrypto_Cipher_CAST", typeof (IronPyCrypto.Cipher.CAST))]

namespace IronPyCrypto.Cipher
{
    public class CAST : IBlockCipher
    {
        public const string __doc__ = "";
        public const int MODE_ECB = 1;
        public const int MODE_CBC = 2;
        public const int MODE_CFB = 3;
        public const int MODE_PGP = 4;
        public const int MODE_OFB = 5;
        public const int MODE_CTR = 6;
        public IBlockCipher mcipher;
        public int mode;
        public byte[] key;
        public byte[] IV;
        public static int key_size = 0;
        public static int block_size = 8;

        public int blocksize
        {
            get { return 8; }
        }

        public int bitcount;

        public CAST()
        {
        }

        [Documentation(@"new(key, [mode], [IV]): Return a new CAST encryption object.")]
        public static CAST @new(string key)
        {
            string IV = StringBytes.BytesToString(new byte[block_size]);
            CAST cast = CAST.@new(key, MODE_ECB, IV, 8, null);
            return (CAST) cast;
        }

        public static CAST @new(string key, int mode)
        {
            string IV = StringBytes.BytesToString(new byte[block_size]);
            CAST cast = CAST.@new(key, mode, IV, 8, null);
            return (CAST) cast;
        }

        public static CAST @new(string key, int mode, string IV)
        {
            CAST cast = CAST.@new(key, mode, IV, 8, null);
            return (CAST) cast;
        }

        public static CAST @new(string key, int mode, string IV, _counter counter)
        {
            CAST cast = CAST.@new(key, mode, IV, 8, counter);
            return (CAST) cast;
        }

        public static CAST @new(string key, [ParamDictionary] IDictionary<object,object> kwargs)
        {
            string IV = StringBytes.BytesToString(new byte[block_size]);
            CAST cast = CAST.@new(key, CAST.MODE_ECB, IV, kwargs);
            return (CAST) cast;
        }

        public static CAST @new(string key, int mode, [ParamDictionary] IDictionary<object,object> kwargs)
        {
            string IV = StringBytes.BytesToString(new byte[block_size]);
            CAST cast = CAST.@new(key, mode, IV, kwargs);
            return (CAST) cast;
        }

        public static CAST @new(string key, int mode, string IV, [ParamDictionary] IDictionary<object,object> kwargs)
        {
            // need to process counter and segment_size
            _counter counter = null;
            int segment_size = 8;
            foreach (object karg in kwargs.Keys)
            {
                //Console.WriteLine("key: {0}, value: {1} ", karg, kwargs[karg]);
                string strkey = karg.ToString();
                if (strkey == "segment_size")
                {
                    segment_size = (int) kwargs[karg];
                }
                else if (strkey == "counter")
                {
                    counter = (_counter) kwargs[karg];
                }
                else
                {
                    throw PythonOps.ValueError("unknown keyword argument: {0}", strkey);
                }
            }
            return CAST.@new(key, mode, IV, segment_size, counter);
        }

        private static CAST @new(string key, int mode, string IV, int segment_size, _counter counter)
        {
            if (key.Length == 0)
            {
                throw PythonOps.ValueError("Key cannot be the null string");
            }
            if (IV.Length > 0 && IV.Length != block_size)
            {
                throw PythonOps.ValueError("IV must be {0} bytes long", block_size);
            }
            if (counter != null && mode != MODE_CTR)
            {
                throw PythonOps.ValueError("'counter' parameter only useful with CTR mode");
            }
            CAST cast = new CAST();
            IBlockCipher cipher = CAST_ECB.@new(key);
            if (mode == MODE_CBC)
            {
                cast.mcipher = CBC.@new(cipher, IV);
            }
            else if (mode == MODE_CFB)
            {
                cast.mcipher = CFB.@new(cipher, IV, segment_size);
            }
            else if (mode == MODE_OFB)
            {
                cast.mcipher = OFB.@new(cipher, IV);
            }
            else if (mode == MODE_CTR)
            {
                if (counter == null)
                {
                    throw PythonOps.TypeError("'counter' keyword parameter is required with CTR mode");
                }
                cast.mcipher = CTR.@new(cipher, counter);
            }
            else if (mode == MODE_ECB)
            {
                cast.mcipher = cipher;
            }
            else
            {
                throw PythonOps.ValueError("Unknown cipher feedback mode {0}", mode);
            }
            cast.bitcount = cast.blocksize*8;
            cast.key = StringBytes.StringToBytes(key);
            if (IV != null)
            {
                cast.IV = StringBytes.StringToBytes(IV);
            }
            cast.mode = mode;
            return (CAST) cast;
        }

        [Documentation(@"Encrypt the provided string of binary data.")]
        public string encrypt(string input)
        {
            if ((input.Length%block_size) != 0 &&
                (mode != MODE_CFB) && (mode != MODE_CTR))
            {
                throw PythonOps.ValueError("Input strings must be a multiple of (0) in length",
                                           block_size);
            }
            int i = 0;
            int ilength = input.Length;
            int chunksize;
            StringBuilder outsb = new StringBuilder();
            while (i < ilength)
            {
                string ichunk;
                if (ilength > (i + block_size))
                {
                    chunksize = block_size;
                    ichunk = input.Substring(i, block_size);
                }
                else
                {
                    chunksize = ilength - i;
                    ichunk = input.Substring(i, chunksize);
                    if (mode != CAST.MODE_CTR) // pad everything except CTR mode
                    {
                        int padlen = block_size - chunksize;
                        ichunk = ichunk + StringBytes.BytesToString(new byte[padlen]);
                    }
                }
                outsb.Append(mcipher.encrypt(ichunk));
                i += chunksize;
            }
            return outsb.ToString().Substring(0, ilength);
        }

        [Documentation(@"decrypt(string): Decrypt the provided string of binary data.")]
        public string decrypt(string input)
        {
            if ((input.Length%block_size) != 0 &&
                (mode != MODE_CFB) && (mode != MODE_CTR))
            {
                throw PythonOps.ValueError("Input strings must be a multiple of (0) in length",
                                           block_size);
            }
            int i = 0;
            int ilength = input.Length;
            int chunksize;
            StringBuilder outsb = new StringBuilder();
            while (i < ilength)
            {
                string ichunk;
                if (ilength > (i + block_size))
                {
                    chunksize = block_size;
                    ichunk = input.Substring(i, block_size);
                }
                else
                {
                    chunksize = ilength - i;
                    ichunk = input.Substring(i, chunksize);
                    if (mode != CAST.MODE_CTR) // pad everything except CTR mode
                    {
                        int padlen = block_size - chunksize;
                        ichunk = ichunk + StringBytes.BytesToString(new byte[padlen]);
                    }
                }
                outsb.Append(mcipher.decrypt(ichunk));
                i += chunksize;
            }
            return outsb.ToString().Substring(0, ilength);
        }

        public void Init(bool forencrypt)
        {
            mcipher.Init(forencrypt);
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            return mcipher.ProcessBlock(input, inOff, output, outOff);
        }
    }
}