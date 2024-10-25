#region License
/*
 * Copyright (c) 2024 AdScore Technologies DMCC [AE]
 *
 * Licensed under MIT License;
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#endregion

using System;
using System.Linq;

namespace AdScore.Signature.ByteOperations
{
    public class ByteWriter
    {
        public static ByteWriter Allocate(int size)
        {
            return new ByteWriter(new byte[size], ByteOrder.BIG_ENDIAN);
        }

        private readonly byte[] _data;
        private int _position = 0;
        private readonly ByteOrder _order = ByteOrder.BIG_ENDIAN;

        public ByteWriter(byte[] bytes, ByteOrder order)
        {
            _data = bytes;
            _order = order;
        }

        public ByteWriter Order(ByteOrder newOrder)
        {
            return new ByteWriter(_data, newOrder);
        }

        public byte[] Array()
        {
            return _data.Take(_position).ToArray();
        }

        public void Put(byte[] bytes)
        {
            bytes.CopyTo(_data, _position);
            _position += bytes.Length;
        }

        public void Put(byte b)
        {
            Put(new[] { b });
        }

        public void PutLong(long b)
        {
            Put(BitConverter.GetBytes(b));
        }

        public void PutShort(short b)
        {
            Put(BitConverter.GetBytes(b));
        }

        public void PutInt(int b)
        {
            Put(BitConverter.GetBytes(b));
        }
    }
}
