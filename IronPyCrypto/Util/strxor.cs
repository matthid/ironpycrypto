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

[assembly: PythonModule("IronPyCrypto_Util_strxor", typeof (IronPyCrypto.Util.Strxor))]

namespace IronPyCrypto.Util
{
    public static class Strxor
    {
        // module documentation
        public const string __doc__ = "";

        // method documentation
        [Documentation(@"strxor(a:str, b:str) -> str

Return a XOR b.  Both a and b must have the same length.")]
        public static string strxor(string s1, string s2)
        {
            if (s1.Length != s2.Length)
            {
                throw PythonOps.ValueError("length of both strings must be equal");
            }
            byte[] byt1 = StringBytes.StringToBytes(s1);
            byte[] byt2 = StringBytes.StringToBytes(s2);
            byte[] result = new byte[byt1.Length];
            int cnt = 0;
            foreach (byte b in byt1)
            {
                result[cnt] = (byte) (b ^ byt2[cnt]);
                cnt = cnt + 1;
            }
            return StringBytes.BytesToString(result);
        }

        [Documentation(@"strxor_c(s:str, c:int) -> str
        
Return s XOR chr(c).  c must be in range(256).")]
        public static string strxor_c(string s1, int c1)
        {
            if (c1 < 0 || c1 > 255)
            {
                throw PythonOps.ValueError("c must be in range(256)");
            }
            byte[] byt = StringBytes.StringToBytes(s1);
            byte ch1 = (byte) c1;
            byte[] result = new byte[byt.Length];
            int cnt = 0;
            foreach (byte b in byt)
            {
                result[cnt] = (byte) (b ^ ch1);
                cnt = cnt + 1;
            }
            return StringBytes.BytesToString(result);
        }
    }
}