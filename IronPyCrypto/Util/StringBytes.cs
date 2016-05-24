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
using System.Text;

// This class is not intended to be used from python
// it is public so that I can use the routine when testing from c#

namespace IronPyCrypto.Util
{
    public static class StringBytes
    {
        // Latin1 is a good match for python strings as it encodes
        // all 256 possible characters
        private static Encoding Latin1 = Encoding.GetEncoding("iso-8859-1");

        public static byte[] StringToBytes(string ss)
        {
            return Latin1.GetBytes(ss);
        }

        public static string BytesToString(byte[] byt)
        {
            return Latin1.GetString(byt);
        }

        public static string BytesToHexString(byte[] byt)
        {
            StringBuilder sb = new StringBuilder(byt.Length);
            foreach (byte b in byt)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

        public static string StringToHexString(string ss)
        {
            byte[] byt = StringToBytes(ss);
            return BytesToHexString(byt);
        }

        public static byte[] HexStringToBytes(string ss)
        {
            byte[] byt = new byte[ss.Length/2];
            for (int i = 0; i < ss.Length; i += 2)
            {
                byt[i/2] = Convert.ToByte(ss.Substring(i, 2), 16);
            }
            return byt;
        }

        public static string HexStringToString(string ss)
        {
            return Latin1.GetString(HexStringToBytes(ss));
        }
    }
}