using System;
using IronPyCrypto.Util;

namespace IronPyCrypto.Cipher
{
    public class DES3_ECB : IBlockCipher
    {
        public byte[] key;
        public int keysize;

        public int bitcount;
        private bool initialized = false;
        private bool forencrypt = true;

        public int blocksize
        {
            get { return 8; }
        }

        public DES3_ECB()
        {
        }

        public static DES3_ECB @new(string key)
        {
            DES3_ECB des3 = new DES3_ECB();
            des3.keysize = 7;
            des3.bitcount = des3.blocksize*8;
            des3.key = StringBytes.StringToBytes(key);
            return des3;
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
            }
            int ilength = input.Length;
            byte[] binput = new byte[blocksize];
            if (ilength > blocksize)
                ilength = blocksize;
            Buffer.BlockCopy(input, 0, binput, 0, ilength);
            byte[] output = new byte[blocksize];
            int bprocessed = ProcessBlock(binput, 0, output, 0);
            return output;
        }

        // From here down this code is ALMOST a simple copy of the code from BouncyCastle

        private int[] workingKey1, workingKey2, workingKey3;

        /**
        * initialise a DES cipher.
        *
        * @param forEncryption whether or not we are for encryption.
        * @param parameters the parameters required to set up the cipher.
        * @exception ArgumentException if the parameters argument is
        * inappropriate.
        */

        public void Init(bool encrypt)
        {
            initialized = true;
            forencrypt = encrypt;
            byte[] key1 = new byte[8], key2 = new byte[8], key3 = new byte[8];
            if (key.Length == 24)
            {
                Array.Copy(key, 0, key1, 0, key1.Length);
                Array.Copy(key, 8, key2, 0, key2.Length);
                Array.Copy(key, 16, key3, 0, key3.Length);
                workingKey1 = DES_ECB.GenerateWorkingKey(encrypt, key1);
                workingKey2 = DES_ECB.GenerateWorkingKey(!encrypt, key2);
                workingKey3 = DES_ECB.GenerateWorkingKey(encrypt, key3);
            }
            else // 16 byte key
            {
                Array.Copy(key, 0, key1, 0, key1.Length);
                Array.Copy(key, 8, key2, 0, key2.Length);
                workingKey1 = DES_ECB.GenerateWorkingKey(encrypt, key1);
                workingKey2 = DES_ECB.GenerateWorkingKey(!encrypt, key2);
                workingKey3 = workingKey1;
            }
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (forencrypt)
            {
                DES_ECB.DesFunc(workingKey1, input, inOff, output, outOff);
                DES_ECB.DesFunc(workingKey2, output, outOff, output, outOff);
                DES_ECB.DesFunc(workingKey3, output, outOff, output, outOff);
            }
            else
            {
                DES_ECB.DesFunc(workingKey3, input, inOff, output, outOff);
                DES_ECB.DesFunc(workingKey2, output, outOff, output, outOff);
                DES_ECB.DesFunc(workingKey1, output, outOff, output, outOff);
            }

            return blocksize;
        }
    }
}