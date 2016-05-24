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
using IronPython.Runtime.Operations;

namespace IronPyCrypto.Cipher
{
    public class AES_ECB : IBlockCipher
    {
        public byte[] key;
        public int keysize;

        public int bitcount;
        private bool initialized = false;
        private bool forencrypt = true;

        public int blocksize
        {
            get { return 16; }
        }

        public AES_ECB()
        {
        }

        public static AES_ECB @new(string key)
        {
            AES_ECB aes = new AES_ECB();
            aes.keysize = 24;
            aes.bitcount = aes.blocksize*8;
            aes.key = StringBytes.StringToBytes(key);
            return aes;
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

        public void Init(bool encrypt)
        {
            initialized = true;
            forencrypt = encrypt;
            WorkingKey = GenerateWorkingKey();
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (WorkingKey == null)
            {
                throw PythonOps.RuntimeError("AES engine not initialised");
            }

            if ((inOff + blocksize) > input.Length)
            {
                throw PythonOps.RuntimeError("input buffer too short");
            }

            if ((outOff + blocksize) > output.Length)
            {
                throw PythonOps.RuntimeError("output buffer too short");
            }

            UnPackBlock(input, inOff);

            if (forencrypt)
            {
                EncryptBlock(WorkingKey);
            }
            else
            {
                DecryptBlock(WorkingKey);
            }

            PackBlock(output, outOff);

            return 16;
        }

        // The S box
        private static readonly byte[] S = {
                                               99,
                                               124,
                                               119,
                                               123,
                                               242,
                                               107,
                                               111,
                                               197,
                                               48,
                                               1,
                                               103,
                                               43,
                                               254,
                                               215,
                                               171,
                                               118,
                                               202,
                                               130,
                                               201,
                                               125,
                                               250,
                                               89,
                                               71,
                                               240,
                                               173,
                                               212,
                                               162,
                                               175,
                                               156,
                                               164,
                                               114,
                                               192,
                                               183,
                                               253,
                                               147,
                                               38,
                                               54,
                                               63,
                                               247,
                                               204,
                                               52,
                                               165,
                                               229,
                                               241,
                                               113,
                                               216,
                                               49,
                                               21,
                                               4,
                                               199,
                                               35,
                                               195,
                                               24,
                                               150,
                                               5,
                                               154,
                                               7,
                                               18,
                                               128,
                                               226,
                                               235,
                                               39,
                                               178,
                                               117,
                                               9,
                                               131,
                                               44,
                                               26,
                                               27,
                                               110,
                                               90,
                                               160,
                                               82,
                                               59,
                                               214,
                                               179,
                                               41,
                                               227,
                                               47,
                                               132,
                                               83,
                                               209,
                                               0,
                                               237,
                                               32,
                                               252,
                                               177,
                                               91,
                                               106,
                                               203,
                                               190,
                                               57,
                                               74,
                                               76,
                                               88,
                                               207,
                                               208,
                                               239,
                                               170,
                                               251,
                                               67,
                                               77,
                                               51,
                                               133,
                                               69,
                                               249,
                                               2,
                                               127,
                                               80,
                                               60,
                                               159,
                                               168,
                                               81,
                                               163,
                                               64,
                                               143,
                                               146,
                                               157,
                                               56,
                                               245,
                                               188,
                                               182,
                                               218,
                                               33,
                                               16,
                                               255,
                                               243,
                                               210,
                                               205,
                                               12,
                                               19,
                                               236,
                                               95,
                                               151,
                                               68,
                                               23,
                                               196,
                                               167,
                                               126,
                                               61,
                                               100,
                                               93,
                                               25,
                                               115,
                                               96,
                                               129,
                                               79,
                                               220,
                                               34,
                                               42,
                                               144,
                                               136,
                                               70,
                                               238,
                                               184,
                                               20,
                                               222,
                                               94,
                                               11,
                                               219,
                                               224,
                                               50,
                                               58,
                                               10,
                                               73,
                                               6,
                                               36,
                                               92,
                                               194,
                                               211,
                                               172,
                                               98,
                                               145,
                                               149,
                                               228,
                                               121,
                                               231,
                                               200,
                                               55,
                                               109,
                                               141,
                                               213,
                                               78,
                                               169,
                                               108,
                                               86,
                                               244,
                                               234,
                                               101,
                                               122,
                                               174,
                                               8,
                                               186,
                                               120,
                                               37,
                                               46,
                                               28,
                                               166,
                                               180,
                                               198,
                                               232,
                                               221,
                                               116,
                                               31,
                                               75,
                                               189,
                                               139,
                                               138,
                                               112,
                                               62,
                                               181,
                                               102,
                                               72,
                                               3,
                                               246,
                                               14,
                                               97,
                                               53,
                                               87,
                                               185,
                                               134,
                                               193,
                                               29,
                                               158,
                                               225,
                                               248,
                                               152,
                                               17,
                                               105,
                                               217,
                                               142,
                                               148,
                                               155,
                                               30,
                                               135,
                                               233,
                                               206,
                                               85,
                                               40,
                                               223,
                                               140,
                                               161,
                                               137,
                                               13,
                                               191,
                                               230,
                                               66,
                                               104,
                                               65,
                                               153,
                                               45,
                                               15,
                                               176,
                                               84,
                                               187,
                                               22
                                           };

        // The inverse S-box
        private static readonly byte[] Si = {
                                                82,
                                                9,
                                                106,
                                                213,
                                                48,
                                                54,
                                                165,
                                                56,
                                                191,
                                                64,
                                                163,
                                                158,
                                                129,
                                                243,
                                                215,
                                                251,
                                                124,
                                                227,
                                                57,
                                                130,
                                                155,
                                                47,
                                                255,
                                                135,
                                                52,
                                                142,
                                                67,
                                                68,
                                                196,
                                                222,
                                                233,
                                                203,
                                                84,
                                                123,
                                                148,
                                                50,
                                                166,
                                                194,
                                                35,
                                                61,
                                                238,
                                                76,
                                                149,
                                                11,
                                                66,
                                                250,
                                                195,
                                                78,
                                                8,
                                                46,
                                                161,
                                                102,
                                                40,
                                                217,
                                                36,
                                                178,
                                                118,
                                                91,
                                                162,
                                                73,
                                                109,
                                                139,
                                                209,
                                                37,
                                                114,
                                                248,
                                                246,
                                                100,
                                                134,
                                                104,
                                                152,
                                                22,
                                                212,
                                                164,
                                                92,
                                                204,
                                                93,
                                                101,
                                                182,
                                                146,
                                                108,
                                                112,
                                                72,
                                                80,
                                                253,
                                                237,
                                                185,
                                                218,
                                                94,
                                                21,
                                                70,
                                                87,
                                                167,
                                                141,
                                                157,
                                                132,
                                                144,
                                                216,
                                                171,
                                                0,
                                                140,
                                                188,
                                                211,
                                                10,
                                                247,
                                                228,
                                                88,
                                                5,
                                                184,
                                                179,
                                                69,
                                                6,
                                                208,
                                                44,
                                                30,
                                                143,
                                                202,
                                                63,
                                                15,
                                                2,
                                                193,
                                                175,
                                                189,
                                                3,
                                                1,
                                                19,
                                                138,
                                                107,
                                                58,
                                                145,
                                                17,
                                                65,
                                                79,
                                                103,
                                                220,
                                                234,
                                                151,
                                                242,
                                                207,
                                                206,
                                                240,
                                                180,
                                                230,
                                                115,
                                                150,
                                                172,
                                                116,
                                                34,
                                                231,
                                                173,
                                                53,
                                                133,
                                                226,
                                                249,
                                                55,
                                                232,
                                                28,
                                                117,
                                                223,
                                                110,
                                                71,
                                                241,
                                                26,
                                                113,
                                                29,
                                                41,
                                                197,
                                                137,
                                                111,
                                                183,
                                                98,
                                                14,
                                                170,
                                                24,
                                                190,
                                                27,
                                                252,
                                                86,
                                                62,
                                                75,
                                                198,
                                                210,
                                                121,
                                                32,
                                                154,
                                                219,
                                                192,
                                                254,
                                                120,
                                                205,
                                                90,
                                                244,
                                                31,
                                                221,
                                                168,
                                                51,
                                                136,
                                                7,
                                                199,
                                                49,
                                                177,
                                                18,
                                                16,
                                                89,
                                                39,
                                                128,
                                                236,
                                                95,
                                                96,
                                                81,
                                                127,
                                                169,
                                                25,
                                                181,
                                                74,
                                                13,
                                                45,
                                                229,
                                                122,
                                                159,
                                                147,
                                                201,
                                                156,
                                                239,
                                                160,
                                                224,
                                                59,
                                                77,
                                                174,
                                                42,
                                                245,
                                                176,
                                                200,
                                                235,
                                                187,
                                                60,
                                                131,
                                                83,
                                                153,
                                                97,
                                                23,
                                                43,
                                                4,
                                                126,
                                                186,
                                                119,
                                                214,
                                                38,
                                                225,
                                                105,
                                                20,
                                                99,
                                                85,
                                                33,
                                                12,
                                                125
                                            };

        // vector used in calculating key schedule (powers of x in GF(256))
        private static readonly byte[] rcon = {
                                                  0x1,
                                                  0x2,
                                                  0x4,
                                                  0x8,
                                                  0x10,
                                                  0x20,
                                                  0x40,
                                                  0x80,
                                                  0x1b,
                                                  0x36,
                                                  0x6c,
                                                  0xd8,
                                                  0xab,
                                                  0x4d,
                                                  0x9a,
                                                  0x2f,
                                                  0x5e,
                                                  0xbc,
                                                  0x63,
                                                  0xc6,
                                                  0x97,
                                                  0x35,
                                                  0x6a,
                                                  0xd4,
                                                  0xb3,
                                                  0x7d,
                                                  0xfa,
                                                  0xef,
                                                  0xc5,
                                                  0x91
                                              };

        // precomputation tables of calculations for rounds
        private static readonly uint[] T0 = {
                                                0xa56363c6u,
                                                0x847c7cf8u,
                                                0x997777eeu,
                                                0x8d7b7bf6u,
                                                0xdf2f2ff,
                                                0xbd6b6bd6u,
                                                0xb16f6fdeu,
                                                0x54c5c591,
                                                0x50303060,
                                                0x3010102,
                                                0xa96767ceu,
                                                0x7d2b2b56,
                                                0x19fefee7,
                                                0x62d7d7b5,
                                                0xe6abab4du,
                                                0x9a7676ecu,
                                                0x45caca8f,
                                                0x9d82821fu,
                                                0x40c9c989,
                                                0x877d7dfau,
                                                0x15fafaef,
                                                0xeb5959b2u,
                                                0xc947478eu,
                                                0xbf0f0fb,
                                                0xecadad41u,
                                                0x67d4d4b3,
                                                0xfda2a25fu,
                                                0xeaafaf45u,
                                                0xbf9c9c23u,
                                                0xf7a4a453u,
                                                0x967272e4u,
                                                0x5bc0c09b,
                                                0xc2b7b775u,
                                                0x1cfdfde1,
                                                0xae93933du,
                                                0x6a26264c,
                                                0x5a36366c,
                                                0x413f3f7e,
                                                0x2f7f7f5,
                                                0x4fcccc83,
                                                0x5c343468,
                                                0xf4a5a551u,
                                                0x34e5e5d1,
                                                0x8f1f1f9,
                                                0x937171e2u,
                                                0x73d8d8ab,
                                                0x53313162,
                                                0x3f15152a,
                                                0xc040408,
                                                0x52c7c795,
                                                0x65232346,
                                                0x5ec3c39d,
                                                0x28181830,
                                                0xa1969637u,
                                                0xf05050a,
                                                0xb59a9a2fu,
                                                0x907070e,
                                                0x36121224,
                                                0x9b80801bu,
                                                0x3de2e2df,
                                                0x26ebebcd,
                                                0x6927274e,
                                                0xcdb2b27fu,
                                                0x9f7575eau,
                                                0x1b090912,
                                                0x9e83831du,
                                                0x742c2c58,
                                                0x2e1a1a34,
                                                0x2d1b1b36,
                                                0xb26e6edcu,
                                                0xee5a5ab4u,
                                                0xfba0a05bu,
                                                0xf65252a4u,
                                                0x4d3b3b76,
                                                0x61d6d6b7,
                                                0xceb3b37du,
                                                0x7b292952,
                                                0x3ee3e3dd,
                                                0x712f2f5e,
                                                0x97848413u,
                                                0xf55353a6u,
                                                0x68d1d1b9,
                                                0x0,
                                                0x2cededc1,
                                                0x60202040,
                                                0x1ffcfce3,
                                                0xc8b1b179u,
                                                0xed5b5bb6u,
                                                0xbe6a6ad4u,
                                                0x46cbcb8d,
                                                0xd9bebe67u,
                                                0x4b393972,
                                                0xde4a4a94u,
                                                0xd44c4c98u,
                                                0xe85858b0u,
                                                0x4acfcf85,
                                                0x6bd0d0bb,
                                                0x2aefefc5,
                                                0xe5aaaa4fu,
                                                0x16fbfbed,
                                                0xc5434386u,
                                                0xd74d4d9au,
                                                0x55333366,
                                                0x94858511u,
                                                0xcf45458au,
                                                0x10f9f9e9,
                                                0x6020204,
                                                0x817f7ffeu,
                                                0xf05050a0u,
                                                0x443c3c78,
                                                0xba9f9f25u,
                                                0xe3a8a84bu,
                                                0xf35151a2u,
                                                0xfea3a35du,
                                                0xc0404080u,
                                                0x8a8f8f05u,
                                                0xad92923fu,
                                                0xbc9d9d21u,
                                                0x48383870,
                                                0x4f5f5f1,
                                                0xdfbcbc63u,
                                                0xc1b6b677u,
                                                0x75dadaaf,
                                                0x63212142,
                                                0x30101020,
                                                0x1affffe5,
                                                0xef3f3fd,
                                                0x6dd2d2bf,
                                                0x4ccdcd81,
                                                0x140c0c18,
                                                0x35131326,
                                                0x2fececc3,
                                                0xe15f5fbeu,
                                                0xa2979735u,
                                                0xcc444488u,
                                                0x3917172e,
                                                0x57c4c493,
                                                0xf2a7a755u,
                                                0x827e7efcu,
                                                0x473d3d7a,
                                                0xac6464c8u,
                                                0xe75d5dbau,
                                                0x2b191932,
                                                0x957373e6u,
                                                0xa06060c0u,
                                                0x98818119u,
                                                0xd14f4f9eu,
                                                0x7fdcdca3,
                                                0x66222244,
                                                0x7e2a2a54,
                                                0xab90903bu,
                                                0x8388880bu,
                                                0xca46468cu,
                                                0x29eeeec7,
                                                0xd3b8b86bu,
                                                0x3c141428,
                                                0x79dedea7,
                                                0xe25e5ebcu,
                                                0x1d0b0b16,
                                                0x76dbdbad,
                                                0x3be0e0db,
                                                0x56323264,
                                                0x4e3a3a74,
                                                0x1e0a0a14,
                                                0xdb494992u,
                                                0xa06060c,
                                                0x6c242448,
                                                0xe45c5cb8u,
                                                0x5dc2c29f,
                                                0x6ed3d3bd,
                                                0xefacac43u,
                                                0xa66262c4u,
                                                0xa8919139u,
                                                0xa4959531u,
                                                0x37e4e4d3,
                                                0x8b7979f2u,
                                                0x32e7e7d5,
                                                0x43c8c88b,
                                                0x5937376e,
                                                0xb76d6ddau,
                                                0x8c8d8d01u,
                                                0x64d5d5b1,
                                                0xd24e4e9cu,
                                                0xe0a9a949u,
                                                0xb46c6cd8u,
                                                0xfa5656acu,
                                                0x7f4f4f3,
                                                0x25eaeacf,
                                                0xaf6565cau,
                                                0x8e7a7af4u,
                                                0xe9aeae47u,
                                                0x18080810,
                                                0xd5baba6fu,
                                                0x887878f0u,
                                                0x6f25254a,
                                                0x722e2e5c,
                                                0x241c1c38,
                                                0xf1a6a657u,
                                                0xc7b4b473u,
                                                0x51c6c697,
                                                0x23e8e8cb,
                                                0x7cdddda1,
                                                0x9c7474e8u,
                                                0x211f1f3e,
                                                0xdd4b4b96u,
                                                0xdcbdbd61u,
                                                0x868b8b0du,
                                                0x858a8a0fu,
                                                0x907070e0u,
                                                0x423e3e7c,
                                                0xc4b5b571u,
                                                0xaa6666ccu,
                                                0xd8484890u,
                                                0x5030306,
                                                0x1f6f6f7,
                                                0x120e0e1c,
                                                0xa36161c2u,
                                                0x5f35356a,
                                                0xf95757aeu,
                                                0xd0b9b969u,
                                                0x91868617u,
                                                0x58c1c199,
                                                0x271d1d3a,
                                                0xb99e9e27u,
                                                0x38e1e1d9,
                                                0x13f8f8eb,
                                                0xb398982bu,
                                                0x33111122,
                                                0xbb6969d2u,
                                                0x70d9d9a9,
                                                0x898e8e07u,
                                                0xa7949433u,
                                                0xb69b9b2du,
                                                0x221e1e3c,
                                                0x92878715u,
                                                0x20e9e9c9,
                                                0x49cece87,
                                                0xff5555aau,
                                                0x78282850,
                                                0x7adfdfa5,
                                                0x8f8c8c03u,
                                                0xf8a1a159u,
                                                0x80898909u,
                                                0x170d0d1a,
                                                0xdabfbf65u,
                                                0x31e6e6d7,
                                                0xc6424284u,
                                                0xb86868d0u,
                                                0xc3414182u,
                                                0xb0999929u,
                                                0x772d2d5a,
                                                0x110f0f1e,
                                                0xcbb0b07bu,
                                                0xfc5454a8u,
                                                0xd6bbbb6du,
                                                0x3a16162c
                                            };

        private static readonly uint[] Tinv0 = {
                                                   0x50a7f451,
                                                   0x5365417e,
                                                   0xc3a4171au,
                                                   0x965e273au,
                                                   0xcb6bab3bu,
                                                   0xf1459d1fu,
                                                   0xab58faacu,
                                                   0x9303e34bu,
                                                   0x55fa3020,
                                                   0xf66d76adu,
                                                   0x9176cc88u,
                                                   0x254c02f5,
                                                   0xfcd7e54fu,
                                                   0xd7cb2ac5u,
                                                   0x80443526u,
                                                   0x8fa362b5u,
                                                   0x495ab1de,
                                                   0x671bba25,
                                                   0x980eea45u,
                                                   0xe1c0fe5du,
                                                   0x2752fc3,
                                                   0x12f04c81,
                                                   0xa397468du,
                                                   0xc6f9d36bu,
                                                   0xe75f8f03u,
                                                   0x959c9215u,
                                                   0xeb7a6dbfu,
                                                   0xda595295u,
                                                   0x2d83bed4,
                                                   0xd3217458u,
                                                   0x2969e049,
                                                   0x44c8c98e,
                                                   0x6a89c275,
                                                   0x78798ef4,
                                                   0x6b3e5899,
                                                   0xdd71b927u,
                                                   0xb64fe1beu,
                                                   0x17ad88f0,
                                                   0x66ac20c9,
                                                   0xb43ace7du,
                                                   0x184adf63,
                                                   0x82311ae5u,
                                                   0x60335197,
                                                   0x457f5362,
                                                   0xe07764b1u,
                                                   0x84ae6bbbu,
                                                   0x1ca081fe,
                                                   0x942b08f9u,
                                                   0x58684870,
                                                   0x19fd458f,
                                                   0x876cde94u,
                                                   0xb7f87b52u,
                                                   0x23d373ab,
                                                   0xe2024b72u,
                                                   0x578f1fe3,
                                                   0x2aab5566,
                                                   0x728ebb2,
                                                   0x3c2b52f,
                                                   0x9a7bc586u,
                                                   0xa50837d3u,
                                                   0xf2872830u,
                                                   0xb2a5bf23u,
                                                   0xba6a0302u,
                                                   0x5c8216ed,
                                                   0x2b1ccf8a,
                                                   0x92b479a7u,
                                                   0xf0f207f3u,
                                                   0xa1e2694eu,
                                                   0xcdf4da65u,
                                                   0xd5be0506u,
                                                   0x1f6234d1,
                                                   0x8afea6c4u,
                                                   0x9d532e34u,
                                                   0xa055f3a2u,
                                                   0x32e18a05,
                                                   0x75ebf6a4,
                                                   0x39ec830b,
                                                   0xaaef6040u,
                                                   0x69f715e,
                                                   0x51106ebd,
                                                   0xf98a213eu,
                                                   0x3d06dd96,
                                                   0xae053eddu,
                                                   0x46bde64d,
                                                   0xb58d5491u,
                                                   0x55dc471,
                                                   0x6fd40604,
                                                   0xff155060u,
                                                   0x24fb9819,
                                                   0x97e9bdd6u,
                                                   0xcc434089u,
                                                   0x779ed967,
                                                   0xbd42e8b0u,
                                                   0x888b8907u,
                                                   0x385b19e7,
                                                   0xdbeec879u,
                                                   0x470a7ca1,
                                                   0xe90f427cu,
                                                   0xc91e84f8u,
                                                   0x0,
                                                   0x83868009u,
                                                   0x48ed2b32,
                                                   0xac70111eu,
                                                   0x4e725a6c,
                                                   0xfbff0efdu,
                                                   0x5638850f,
                                                   0x1ed5ae3d,
                                                   0x27392d36,
                                                   0x64d90f0a,
                                                   0x21a65c68,
                                                   0xd1545b9bu,
                                                   0x3a2e3624,
                                                   0xb1670a0cu,
                                                   0xfe75793,
                                                   0xd296eeb4u,
                                                   0x9e919b1bu,
                                                   0x4fc5c080,
                                                   0xa220dc61u,
                                                   0x694b775a,
                                                   0x161a121c,
                                                   0xaba93e2,
                                                   0xe52aa0c0u,
                                                   0x43e0223c,
                                                   0x1d171b12,
                                                   0xb0d090e,
                                                   0xadc78bf2u,
                                                   0xb9a8b62du,
                                                   0xc8a91e14u,
                                                   0x8519f157u,
                                                   0x4c0775af,
                                                   0xbbdd99eeu,
                                                   0xfd607fa3u,
                                                   0x9f2601f7u,
                                                   0xbcf5725cu,
                                                   0xc53b6644u,
                                                   0x347efb5b,
                                                   0x7629438b,
                                                   0xdcc623cbu,
                                                   0x68fcedb6,
                                                   0x63f1e4b8,
                                                   0xcadc31d7u,
                                                   0x10856342,
                                                   0x40229713,
                                                   0x2011c684,
                                                   0x7d244a85,
                                                   0xf83dbbd2u,
                                                   0x1132f9ae,
                                                   0x6da129c7,
                                                   0x4b2f9e1d,
                                                   0xf330b2dcu,
                                                   0xec52860du,
                                                   0xd0e3c177u,
                                                   0x6c16b32b,
                                                   0x99b970a9u,
                                                   0xfa489411u,
                                                   0x2264e947,
                                                   0xc48cfca8u,
                                                   0x1a3ff0a0,
                                                   0xd82c7d56u,
                                                   0xef903322u,
                                                   0xc74e4987u,
                                                   0xc1d138d9u,
                                                   0xfea2ca8cu,
                                                   0x360bd498,
                                                   0xcf81f5a6u,
                                                   0x28de7aa5,
                                                   0x268eb7da,
                                                   0xa4bfad3fu,
                                                   0xe49d3a2cu,
                                                   0xd927850,
                                                   0x9bcc5f6au,
                                                   0x62467e54,
                                                   0xc2138df6u,
                                                   0xe8b8d890u,
                                                   0x5ef7392e,
                                                   0xf5afc382u,
                                                   0xbe805d9fu,
                                                   0x7c93d069,
                                                   0xa92dd56fu,
                                                   0xb31225cfu,
                                                   0x3b99acc8,
                                                   0xa77d1810u,
                                                   0x6e639ce8,
                                                   0x7bbb3bdb,
                                                   0x97826cd,
                                                   0xf418596eu,
                                                   0x1b79aec,
                                                   0xa89a4f83u,
                                                   0x656e95e6,
                                                   0x7ee6ffaa,
                                                   0x8cfbc21,
                                                   0xe6e815efu,
                                                   0xd99be7bau,
                                                   0xce366f4au,
                                                   0xd4099feau,
                                                   0xd67cb029u,
                                                   0xafb2a431u,
                                                   0x31233f2a,
                                                   0x3094a5c6,
                                                   0xc066a235u,
                                                   0x37bc4e74,
                                                   0xa6ca82fcu,
                                                   0xb0d090e0u,
                                                   0x15d8a733,
                                                   0x4a9804f1,
                                                   0xf7daec41u,
                                                   0xe50cd7f,
                                                   0x2ff69117,
                                                   0x8dd64d76u,
                                                   0x4db0ef43,
                                                   0x544daacc,
                                                   0xdf0496e4u,
                                                   0xe3b5d19eu,
                                                   0x1b886a4c,
                                                   0xb81f2cc1u,
                                                   0x7f516546,
                                                   0x4ea5e9d,
                                                   0x5d358c01,
                                                   0x737487fa,
                                                   0x2e410bfb,
                                                   0x5a1d67b3,
                                                   0x52d2db92,
                                                   0x335610e9,
                                                   0x1347d66d,
                                                   0x8c61d79au,
                                                   0x7a0ca137,
                                                   0x8e14f859u,
                                                   0x893c13ebu,
                                                   0xee27a9ceu,
                                                   0x35c961b7,
                                                   0xede51ce1u,
                                                   0x3cb1477a,
                                                   0x59dfd29c,
                                                   0x3f73f255,
                                                   0x79ce1418,
                                                   0xbf37c773u,
                                                   0xeacdf753u,
                                                   0x5baafd5f,
                                                   0x146f3ddf,
                                                   0x86db4478u,
                                                   0x81f3afcau,
                                                   0x3ec468b9,
                                                   0x2c342438,
                                                   0x5f40a3c2,
                                                   0x72c31d16,
                                                   0xc25e2bc,
                                                   0x8b493c28u,
                                                   0x41950dff,
                                                   0x7101a839,
                                                   0xdeb30c08u,
                                                   0x9ce4b4d8u,
                                                   0x90c15664u,
                                                   0x6184cb7b,
                                                   0x70b632d5,
                                                   0x745c6c48,
                                                   0x4257b8d0
                                               };

        private uint Shift(uint r, int shift)
        {
            return (r >> shift) | (r << (32 - shift));
        }

        /* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

        private const uint m1 = 0x80808080u;
        private const uint m2 = 0x7f7f7f7f;
        private const uint m3 = 0x1b;

        private uint FFmulX(uint x)
        {
            return ((x & m2) << 1) ^ (((x & m1) >> 7)*m3);
        }

        /*
        The following defines provide alternative definitions of FFmulX that might
        give improved performance if a fast 32-bit multiply is not available.

        private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); }
        private static final int  m4 = 0x1b1b1b1b;
        private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); }

        */

        private uint Inv_Mcol(uint x)
        {
            uint f2 = FFmulX(x);
            uint f4 = FFmulX(f2);
            uint f8 = FFmulX(f4);
            uint f9 = x ^ f8;

            return f2 ^ f4 ^ f8 ^ Shift(f2 ^ f9, 8) ^ Shift(f4 ^ f9, 16) ^ Shift(f9, 24);
        }

        private uint SubWord(uint x)
        {
            return (uint) S[x & 255] | (((uint) S[(x >> 8) & 255]) << 8) | (((uint) S[(x >> 16) & 255]) << 16) | (((uint) S[(x >> 24) & 255]) << 24);
        }

        /**
        * Calculate the necessary round keys
        * The number of calculations depends on key size and block size
        * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
        * This code is written assuming those are the only possible values
        */

        private uint[,] GenerateWorkingKey()
        {
            int KC = key.Length/4;
            // key length in words
            int t;

            if ((KC != 4) && (KC != 6) && (KC != 8))
                throw PythonOps.ValueError("Key length not 128/192/256 bits.");

            ROUNDS = KC + 6;
            // This is not always true for the generalized Rijndael that allows larger block sizes
            uint[,] W = new uint[ROUNDS + 1,4];
            // 4 words in a block
            //
            // copy the key into the round key array
            //

            t = 0;
            for (int i = 0; i < key.Length; t++)
            {
                W[t >> 2, t & 3] = Pack.LE_To_UInt32(key, i);
                i += 4;
            }

            //
            // while not enough round key material calculated
            // calculate new values
            //
            int k = (ROUNDS + 1) << 2;
            for (int i = KC; (i < k); i++)
            {
                uint temp = W[(i - 1) >> 2, (i - 1) & 3];
                if ((i%KC) == 0)
                {
                    temp = SubWord(Shift(temp, 8)) ^ rcon[(i/KC) - 1];
                }
                else if ((KC > 6) && ((i%KC) == 4))
                {
                    temp = SubWord(temp);
                }

                W[i >> 2, i & 3] = W[(i - KC) >> 2, (i - KC) & 3] ^ temp;
            }

            if (!forencrypt)
            {
                for (int j = 1; j < ROUNDS; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        W[j, i] = Inv_Mcol(W[j, i]);
                    }
                }
            }

            return W;
        }

        private int ROUNDS;
        private uint[,] WorkingKey;
        private uint C0, C1, C2, C3;

        private void UnPackBlock(byte[] bytes, int off)
        {
            C0 = Pack.LE_To_UInt32(bytes, off);
            C1 = Pack.LE_To_UInt32(bytes, off + 4);
            C2 = Pack.LE_To_UInt32(bytes, off + 8);
            C3 = Pack.LE_To_UInt32(bytes, off + 12);
        }

        private void PackBlock(byte[] bytes, int off)
        {
            Pack.UInt32_To_LE(C0, bytes, off);
            Pack.UInt32_To_LE(C1, bytes, off + 4);
            Pack.UInt32_To_LE(C2, bytes, off + 8);
            Pack.UInt32_To_LE(C3, bytes, off + 12);
        }

        private void EncryptBlock(uint[,] KW)
        {
            uint r, r0, r1, r2, r3;

            C0 ^= KW[0, 0];
            C1 ^= KW[0, 1];
            C2 ^= KW[0, 2];
            C3 ^= KW[0, 3];

            for (r = 1; r < ROUNDS - 1;)
            {
                r0 = T0[C0 & 255] ^ Shift(T0[(C1 >> 8) & 255], 24) ^ Shift(T0[(C2 >> 16) & 255], 16) ^ Shift(T0[(C3 >> 24) & 255], 8) ^ KW[r, 0];
                r1 = T0[C1 & 255] ^ Shift(T0[(C2 >> 8) & 255], 24) ^ Shift(T0[(C3 >> 16) & 255], 16) ^ Shift(T0[(C0 >> 24) & 255], 8) ^ KW[r, 1];
                r2 = T0[C2 & 255] ^ Shift(T0[(C3 >> 8) & 255], 24) ^ Shift(T0[(C0 >> 16) & 255], 16) ^ Shift(T0[(C1 >> 24) & 255], 8) ^ KW[r, 2];
                r3 = T0[C3 & 255] ^ Shift(T0[(C0 >> 8) & 255], 24) ^ Shift(T0[(C1 >> 16) & 255], 16) ^ Shift(T0[(C2 >> 24) & 255], 8) ^ KW[r++, 3];
                C0 = T0[r0 & 255] ^ Shift(T0[(r1 >> 8) & 255], 24) ^ Shift(T0[(r2 >> 16) & 255], 16) ^ Shift(T0[(r3 >> 24) & 255], 8) ^ KW[r, 0];
                C1 = T0[r1 & 255] ^ Shift(T0[(r2 >> 8) & 255], 24) ^ Shift(T0[(r3 >> 16) & 255], 16) ^ Shift(T0[(r0 >> 24) & 255], 8) ^ KW[r, 1];
                C2 = T0[r2 & 255] ^ Shift(T0[(r3 >> 8) & 255], 24) ^ Shift(T0[(r0 >> 16) & 255], 16) ^ Shift(T0[(r1 >> 24) & 255], 8) ^ KW[r, 2];
                C3 = T0[r3 & 255] ^ Shift(T0[(r0 >> 8) & 255], 24) ^ Shift(T0[(r1 >> 16) & 255], 16) ^ Shift(T0[(r2 >> 24) & 255], 8) ^ KW[r++, 3];
            }

            r0 = T0[C0 & 255] ^ Shift(T0[(C1 >> 8) & 255], 24) ^ Shift(T0[(C2 >> 16) & 255], 16) ^ Shift(T0[(C3 >> 24) & 255], 8) ^ KW[r, 0];
            r1 = T0[C1 & 255] ^ Shift(T0[(C2 >> 8) & 255], 24) ^ Shift(T0[(C3 >> 16) & 255], 16) ^ Shift(T0[(C0 >> 24) & 255], 8) ^ KW[r, 1];
            r2 = T0[C2 & 255] ^ Shift(T0[(C3 >> 8) & 255], 24) ^ Shift(T0[(C0 >> 16) & 255], 16) ^ Shift(T0[(C1 >> 24) & 255], 8) ^ KW[r, 2];
            r3 = T0[C3 & 255] ^ Shift(T0[(C0 >> 8) & 255], 24) ^ Shift(T0[(C1 >> 16) & 255], 16) ^ Shift(T0[(C2 >> 24) & 255], 8) ^ KW[r++, 3];

            // the final round's table is a simple function of S so we don't use a whole other four tables for it

            C0 = (uint) S[r0 & 255] ^ (((uint) S[(r1 >> 8) & 255]) << 8) ^ (((uint) S[(r2 >> 16) & 255]) << 16) ^ (((uint) S[(r3 >> 24) & 255]) << 24) ^
                 KW[r, 0];
            C1 = (uint) S[r1 & 255] ^ (((uint) S[(r2 >> 8) & 255]) << 8) ^ (((uint) S[(r3 >> 16) & 255]) << 16) ^ (((uint) S[(r0 >> 24) & 255]) << 24) ^
                 KW[r, 1];
            C2 = (uint) S[r2 & 255] ^ (((uint) S[(r3 >> 8) & 255]) << 8) ^ (((uint) S[(r0 >> 16) & 255]) << 16) ^ (((uint) S[(r1 >> 24) & 255]) << 24) ^
                 KW[r, 2];
            C3 = (uint) S[r3 & 255] ^ (((uint) S[(r0 >> 8) & 255]) << 8) ^ (((uint) S[(r1 >> 16) & 255]) << 16) ^ (((uint) S[(r2 >> 24) & 255]) << 24) ^
                 KW[r, 3];
        }

        private void DecryptBlock(uint[,] KW)
        {
            int r;
            uint r0, r1, r2, r3;

            C0 ^= KW[ROUNDS, 0];
            C1 ^= KW[ROUNDS, 1];
            C2 ^= KW[ROUNDS, 2];
            C3 ^= KW[ROUNDS, 3];

            for (r = ROUNDS - 1; r > 1;)
            {
                r0 = Tinv0[C0 & 255] ^ Shift(Tinv0[(C3 >> 8) & 255], 24) ^ Shift(Tinv0[(C2 >> 16) & 255], 16) ^ Shift(Tinv0[(C1 >> 24) & 255], 8) ^
                     KW[r, 0];
                r1 = Tinv0[C1 & 255] ^ Shift(Tinv0[(C0 >> 8) & 255], 24) ^ Shift(Tinv0[(C3 >> 16) & 255], 16) ^ Shift(Tinv0[(C2 >> 24) & 255], 8) ^
                     KW[r, 1];
                r2 = Tinv0[C2 & 255] ^ Shift(Tinv0[(C1 >> 8) & 255], 24) ^ Shift(Tinv0[(C0 >> 16) & 255], 16) ^ Shift(Tinv0[(C3 >> 24) & 255], 8) ^
                     KW[r, 2];
                r3 = Tinv0[C3 & 255] ^ Shift(Tinv0[(C2 >> 8) & 255], 24) ^ Shift(Tinv0[(C1 >> 16) & 255], 16) ^ Shift(Tinv0[(C0 >> 24) & 255], 8) ^
                     KW[r--, 3];
                C0 = Tinv0[r0 & 255] ^ Shift(Tinv0[(r3 >> 8) & 255], 24) ^ Shift(Tinv0[(r2 >> 16) & 255], 16) ^ Shift(Tinv0[(r1 >> 24) & 255], 8) ^
                     KW[r, 0];
                C1 = Tinv0[r1 & 255] ^ Shift(Tinv0[(r0 >> 8) & 255], 24) ^ Shift(Tinv0[(r3 >> 16) & 255], 16) ^ Shift(Tinv0[(r2 >> 24) & 255], 8) ^
                     KW[r, 1];
                C2 = Tinv0[r2 & 255] ^ Shift(Tinv0[(r1 >> 8) & 255], 24) ^ Shift(Tinv0[(r0 >> 16) & 255], 16) ^ Shift(Tinv0[(r3 >> 24) & 255], 8) ^
                     KW[r, 2];
                C3 = Tinv0[r3 & 255] ^ Shift(Tinv0[(r2 >> 8) & 255], 24) ^ Shift(Tinv0[(r1 >> 16) & 255], 16) ^ Shift(Tinv0[(r0 >> 24) & 255], 8) ^
                     KW[r--, 3];
            }

            r0 = Tinv0[C0 & 255] ^ Shift(Tinv0[(C3 >> 8) & 255], 24) ^ Shift(Tinv0[(C2 >> 16) & 255], 16) ^ Shift(Tinv0[(C1 >> 24) & 255], 8) ^
                 KW[r, 0];
            r1 = Tinv0[C1 & 255] ^ Shift(Tinv0[(C0 >> 8) & 255], 24) ^ Shift(Tinv0[(C3 >> 16) & 255], 16) ^ Shift(Tinv0[(C2 >> 24) & 255], 8) ^
                 KW[r, 1];
            r2 = Tinv0[C2 & 255] ^ Shift(Tinv0[(C1 >> 8) & 255], 24) ^ Shift(Tinv0[(C0 >> 16) & 255], 16) ^ Shift(Tinv0[(C3 >> 24) & 255], 8) ^
                 KW[r, 2];
            r3 = Tinv0[C3 & 255] ^ Shift(Tinv0[(C2 >> 8) & 255], 24) ^ Shift(Tinv0[(C1 >> 16) & 255], 16) ^ Shift(Tinv0[(C0 >> 24) & 255], 8) ^
                 KW[r, 3];

            // the final round's table is a simple function of Si so we don't use a whole other four tables for it

            C0 = (uint) Si[r0 & 255] ^ (((uint) Si[(r3 >> 8) & 255]) << 8) ^ (((uint) Si[(r2 >> 16) & 255]) << 16) ^
                 (((uint) Si[(r1 >> 24) & 255]) << 24) ^ KW[0, 0];
            C1 = (uint) Si[r1 & 255] ^ (((uint) Si[(r0 >> 8) & 255]) << 8) ^ (((uint) Si[(r3 >> 16) & 255]) << 16) ^
                 (((uint) Si[(r2 >> 24) & 255]) << 24) ^ KW[0, 1];
            C2 = (uint) Si[r2 & 255] ^ (((uint) Si[(r1 >> 8) & 255]) << 8) ^ (((uint) Si[(r0 >> 16) & 255]) << 16) ^
                 (((uint) Si[(r3 >> 24) & 255]) << 24) ^ KW[0, 2];
            C3 = (uint) Si[r3 & 255] ^ (((uint) Si[(r2 >> 8) & 255]) << 8) ^ (((uint) Si[(r1 >> 16) & 255]) << 16) ^
                 (((uint) Si[(r0 >> 24) & 255]) << 24) ^ KW[0, 3];
        }
    }
}