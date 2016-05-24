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
using System.Security.Cryptography;
using IronPyCrypto.Util;
using IronPython.Runtime;
using Microsoft.Scripting.Runtime;

[assembly: PythonModule("IronPyCrypto_Random_OSRNG_winrandom", typeof (IronPyCrypto.Random.OSRNG.winrandom))]

namespace IronPyCrypto.Random.OSRNG
{
    /// <summary>
    /// class with just one method (get_bytes)
    /// </summary>
    public class winrandom
    {
        public static string __doc__ =
            @"new([provider], [provtype]): Returns an object handle to Windows
CryptoAPI that can be used to access a cryptographically strong
pseudo-random generator that uses OS-gathered entropy.
Provider is a string that specifies the Cryptographic Service Provider
to use, default is the default OS CSP.
provtype is an integer specifying the provider type to use, default
is 1 (PROV_RSA_FULL)";

        // this is just set up to match what is on my system (32 bit XP)
        public const string INTEL_DEF_PROV = "Intel Hardware Cryptographic Service Provider";
        public const string MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";
        public const string MS_DEF_DSS_PROV = "Microsoft Base DSS Cryptographic Provider";
        public const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
        public const string MS_DEF_RSA_SCHANNEL_PROV = "Microsoft RSA SChannel Cryptographic Provider";
        public const string MS_DEF_RSA_SIG_PROV = "Microsoft RSA Signature Cryptographic Provider";
        public const string MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
        public const int PROV_DSS = 3;
        public const int PROV_DSS_DH = 13;
        public const int PROV_EC_ECDSA_FULL = 16;
        public const int PROV_EC_ECDSA_SIG = 14;
        public const int PROV_EC_ECNRA_FULL = 17;
        public const int PROV_EC_ECRNA_SIG = 5;
        public const int PROV_FORTEZZA = 4;
        public const int PROV_INTEL_SEC = 22;
        public const int PROV_MS_EXCHANGE = 5;
        public const int PROV_RSA_FULL = 1;
        public const int PROV_RSA_SCHANNEL = 12;
        public const int PROV_RSA_SIG = 2;
        public const int PROV_SPYRUS_LYNKS = 20;
        public const int PROV_SSL = 6;

        public winrandom()
        {
        }

        public static winrandom @new()
        {
            winrandom w = new winrandom();
            return w;
        }

        // we ignore provider and provtype for now
        public static winrandom @new(string provider)
        {
            winrandom w = new winrandom();
            return w;
        }

        public static winrandom @new(string provider, int provtype)
        {
            winrandom w = new winrandom();
            return w;
        }

        [Documentation(
            @"get_bytes(nbytes, [userdata]]): Returns nbytes of random data
from Windows CryptGenRandom.
userdata is a string with any additional entropic data that the
user wishes to provide."
            )]
        public string get_bytes(int bc)
        {
            byte[] randomness = new Byte[bc];
            //RNGCryptoServiceProvider is an implementation of a random number generator.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            // The array is now filled with cryptographically strong random bytes.
            rng.GetBytes(randomness);
            return StringBytes.BytesToString(randomness);
        }

        public string get_bytes(int bc, string userdata)
        {
            // for the moment we silently throw away the userdata
            return get_bytes(bc);
        }
    }
}