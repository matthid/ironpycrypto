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

namespace IronPyCrypto.Cipher
{
    public class CTR : IBlockCipher
    {
        public IBlockCipher ucipher;
        private bool initialized = false;
        private bool forencrypt = true;
        private _counter counter;
        private byte[] counterOut;
        private int count;

        public int blocksize
        {
            get { return ucipher.blocksize; }
        }

        public CTR()
        {
        }

        public static CTR @new(IBlockCipher cipher, _counter counter)
        {
            CTR ctr = new CTR();
            ctr.ucipher = cipher;
            ctr.counter = counter;
            ctr.counterOut = new byte[counter.Length];
            ctr.count = 0;
            return ctr;
        }

        public string encrypt(string input)
        {
            byte[] binput = StringBytes.StringToBytes(input);
            byte[] result = process(binput, true);
            return StringBytes.BytesToString(result);
        }

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
                initialized = true;
                forencrypt = encrypt;
            }
            int ilength = input.Length;
            if (ilength > ucipher.blocksize)
                ilength = ucipher.blocksize;
            byte[] binput = new byte[ilength];
            Buffer.BlockCopy(input, 0, binput, 0, ilength);
            byte[] output = new byte[ilength];
            int bprocessed = ProcessBlock(binput, 0, output, 0);
            return output;
        }

        public void Init(bool forencrypt)
        {
            //forencrypt is ignored
            this.forencrypt = forencrypt;
            ucipher.Init(true);
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            for (int i = 0; i < input.Length; i++)
            {
                if (count == 0)
                {
                    byte[] c = counter.ToByteArray();
                    ucipher.ProcessBlock(c, 0, counterOut, 0);
                }
                output[outOff + i] = (byte) (counterOut[count] ^ input[inOff + i]);
                count = count + 1;
                if (count >= blocksize)
                {
                    counter.__call__(); // increment the counter
                    count = 0;
                }
            }
            return input.Length;
        }
    }
}