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
using Microsoft.Scripting.Math;

[assembly: PythonModule("IronPyCrypto_Util_counter", typeof (IronPyCrypto.Util._counter))]

namespace IronPyCrypto.Util
{
    public class _counter
    {
        // module documentation
        public const string __doc__ = "";

        private int nbytes;
        private byte[] prefix;
        private byte[] suffix;
        private byte[] val;
        private bool allow_wraparound;
        private bool little_endian;
        private bool disable_shortcut;
        public int carry;

        public bool __PCT_CTR_SHORTCUT__
        {
            // this code fakes the behavior in the real Crypto.Util.Counter where the
            // __PCT_CTR_SHORTCUT__ attribute does not exist if disable_shortcut is true
            // for this library __PCT_CTR_SHORTCUT__ will have no effect!
            get
            {
                if (disable_shortcut)
                {
                    throw PythonOps.AttributeError("_counter object has no attribute __PCT_CTR_SHORTCUT__");
                }
                else return true;
            }
        }

        public int Length
        {
            get { return nbytes; }
        }

        public _counter()
        {
        }

        public static _counter _newBE(string prefix,
                                      string suffix,
                                      string initval,
                                      bool allow_wraparound,
                                      bool disable_shortcut)
        {
            _counter c = new _counter();
            CheckArgs(prefix, suffix, initval);
            c.nbytes = initval.Length + prefix.Length + suffix.Length;
            c.prefix = StringBytes.StringToBytes(prefix);
            c.suffix = StringBytes.StringToBytes(suffix);
            c.val = new byte[initval.Length];
            byte[] binitval = StringBytes.StringToBytes(initval);
            Buffer.BlockCopy(binitval, 0, c.val, 0, c.val.Length);
            c.allow_wraparound = allow_wraparound;
            c.disable_shortcut = disable_shortcut;
            c.little_endian = false;
            c.carry = 0;
            return c;
        }

        public static _counter _newLE(string prefix,
                                      string suffix,
                                      string initval,
                                      bool allow_wraparound,
                                      bool disable_shortcut)
        {
            _counter c = new _counter();
            CheckArgs(prefix, suffix, initval);
            c.nbytes = initval.Length + prefix.Length + suffix.Length;
            c.prefix = StringBytes.StringToBytes(prefix);
            c.suffix = StringBytes.StringToBytes(suffix);
            c.val = new byte[initval.Length];
            byte[] binitval = StringBytes.StringToBytes(initval);
            Buffer.BlockCopy(binitval, 0, c.val, 0, c.val.Length);
            c.allow_wraparound = allow_wraparound;
            c.disable_shortcut = disable_shortcut;
            c.little_endian = true;
            c.carry = 0;
            return c;
        }

        private static void CheckArgs(string prefix, string suffix, string initval)
        {
            if (initval.Length < 1)
            {
                throw PythonOps.ValueError("initval length too small (must be >= 1 byte)");
            }
            if (initval.Length > 0xffff)
            {
                throw PythonOps.ValueError("initval length too large (must be <= 65535 bytes)");
            }
            if (prefix.Length > 0xffff)
            {
                throw PythonOps.ValueError("prefix length too large (must be <= 65535 bytes)");
            }
            if (suffix.Length > 0xffff)
            {
                throw PythonOps.ValueError("suffix length too large (must be <= 65535 bytes)");
            }
        }

        public string __call__()
        {
            // save the counter and then increment it, return the saved counter as a string
            if (!allow_wraparound && carry == 1)
            {
                throw PythonOps.OverflowError("counter wrapped without allow_wraparound");
            }
            byte[] result = ToByteArray();
            carry = increment(val);
            return StringBytes.BytesToString(result);
        }

        public BigInteger next_value()
        {
            if (!allow_wraparound && carry == 1)
            {
                throw PythonOps.OverflowError("counter wrapped without allow_wraparound");
            }
            byte[] temp = new byte[8];
            if (little_endian)
            {
                if (val.Length > 8)
                {
                    Array.Copy(val, 0, temp, 0, 8);
                }
                else
                {
                    Array.Copy(val, 0, temp, 0, val.Length);
                }
                if (!BitConverter.IsLittleEndian) Array.Reverse(temp);
            }
            else
            {
                if (val.Length > 8)
                {
                    Array.Copy(val, val.Length - 8, temp, 0, 8);
                }
                else
                {
                    Array.Copy(val, 0, temp, 8 - val.Length, val.Length);
                }
                if (BitConverter.IsLittleEndian) Array.Reverse(temp);
            }
            return BigInteger.Create(temp);
        }

        private int increment(byte[] bb)
        {
            int c = 1;
            int i;
            if (little_endian)
            {
                for (i = 0; i < bb.Length; i++)
                {
                    c = AddByte(bb, i, c);
                    // we are done if we don't have to carry
                    if (c == 0) break;
                }
            }
            else
            {
                for (i = bb.Length - 1; i >= 0; i--)
                {
                    c = AddByte(bb, i, c);
                    // we are done if we don't have to carry
                    if (c == 0) break;
                }
            }
            return c;
        }

        private int AddByte(byte[] bb, int i, int c)
        {
            byte b = bb[i];
            int r = b + c;
            if (r > 255)
            {
                // set carry, zero the byte
                c = 1;
                bb[i] = 0;
            }
            else
            {
                // carry to zero, update the byte
                c = 0;
                bb[i] = (byte) r;
            }
            return c;
        }

        internal byte[] ToByteArray()
        {
            byte[] result = new byte[nbytes];
            if (little_endian)
            {
                Buffer.BlockCopy(suffix, 0, result, 0, suffix.Length);
                Buffer.BlockCopy(val, 0, result, suffix.Length, val.Length);
                Buffer.BlockCopy(prefix, 0, result, nbytes - prefix.Length, prefix.Length);
            }
            else
            {
                Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
                Buffer.BlockCopy(val, 0, result, prefix.Length, val.Length);
                Buffer.BlockCopy(suffix, 0, result, nbytes - suffix.Length, suffix.Length);
            }
            if (!BitConverter.IsLittleEndian) Array.Reverse(result);
            return result;
        }
    }
}