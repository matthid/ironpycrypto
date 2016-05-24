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

/// This code is copied verbatim from BouncyCastle
/// Used internally only

using System;

namespace IronPyCrypto.Cipher
{
    internal sealed class Pack
    {
        private Pack()
        {
        }

        internal static void UInt32_To_BE(uint n, byte[] bs)
        {
            unchecked
            {
                bs[0] = (byte) (n >> 24);
                bs[1] = (byte) (n >> 16);
                bs[2] = (byte) (n >> 8);
                bs[3] = (byte) (n);
            }
        }

        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
        {
            unchecked
            {
                bs[off++] = (byte) (n >> 24);
                bs[off++] = (byte) (n >> 16);
                bs[off++] = (byte) (n >> 8);
                bs[off] = (byte) (n);
            }
        }

        internal static uint BE_To_UInt32(byte[] bs)
        {
            uint n = (uint) bs[0] << 24;
            n |= (uint) bs[1] << 16;
            n |= (uint) bs[2] << 8;
            n |= (uint) bs[3];
            return n;
        }

        internal static uint BE_To_UInt32(byte[] bs, int off)
        {
            uint n = (uint) bs[off++] << 24;
            n |= (uint) bs[off++] << 16;
            n |= (uint) bs[off++] << 8;
            n |= (uint) bs[off];
            return n;
        }

        internal static void UInt32_To_LE(uint n, byte[] bs)
        {
            unchecked
            {
                bs[0] = (byte) (n);
                bs[1] = (byte) (n >> 8);
                bs[2] = (byte) (n >> 16);
                bs[3] = (byte) (n >> 24);
            }
        }

        internal static void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            unchecked
            {
                bs[off++] = (byte) (n);
                bs[off++] = (byte) (n >> 8);
                bs[off++] = (byte) (n >> 16);
                bs[off] = (byte) (n >> 24);
            }
        }

        internal static uint LE_To_UInt32(byte[] bs)
        {
            uint n = (uint) bs[0];
            n |= (uint) bs[1] << 8;
            n |= (uint) bs[2] << 16;
            n |= (uint) bs[3] << 24;
            return n;
        }

        internal static uint LE_To_UInt32(byte[] bs, int off)
        {
            uint n = (uint) bs[off++];
            n |= (uint) bs[off++] << 8;
            n |= (uint) bs[off++] << 16;
            n |= (uint) bs[off] << 24;
            return n;
        }
    }
}