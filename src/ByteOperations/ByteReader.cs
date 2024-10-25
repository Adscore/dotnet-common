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
    public class ByteReader
    {
        public static ByteReader Wrap(byte[] s)
        {
            return new ByteReader(s, ByteOrder.BIG_ENDIAN);
        }

        private readonly byte[] _data;
        private readonly int _from = 0;
        private readonly int _to = 0;
        private readonly ByteOrder _order = ByteOrder.BIG_ENDIAN;

        public int Position { get; set; } = 0;

        public ByteReader(byte[] data, ByteOrder order) : this(data, 0, data.Length, order)
        {
        }

        public ByteReader(byte[] data, int from, int to, ByteOrder order)
        {
            _data = data;
            _from = from;
            _to = to;
            _order = order;
        }

        public byte Get() => GetBytes(1)[0];
        public short GetShort() => BitConverter.ToInt16(GetBytes(2), 0);
        public int GetInt() => BitConverter.ToInt32(GetBytes(4), 0);
        public long GetLong() => BitConverter.ToInt64(GetBytes(8), 0);
        public void Get(byte[] arr)
        {
            byte[] bytes = GetBytes(arr.Length, ignoreOrder: true);
            bytes.CopyTo(arr, 0);
        }

        public bool HasRemaining() => Position < _data.Length;

        public long Capacity => _to - _from;

        public byte[] Array()
        {
            return _data.Skip(_from).Take(_to - _from).ToArray();
        }

        public ByteReader SubBuffer(int offset, int? length = null)
        {
            return new ByteReader(_data, _from + offset, length == null ? _to : _from + offset + length.Value, _order);
        }

        public ByteReader Slice()
        {
            return SubBuffer(Position);
        }

        public ByteReader Order(ByteOrder newOrder)
        {
            return new ByteReader(_data, _from, _to, newOrder);
        }

        private byte[] GetBytes(int size, bool ignoreOrder = false)
        {
            var range = Enumerable.Range(PositionInternal(), size);
            if (!ignoreOrder && _order == ByteOrder.BIG_ENDIAN)
            {
                range = range.Reverse();
            }

            byte[] subArray = range.Select(i => _data[i]).ToArray();
            Position += size;
            return subArray;
        }

        private int PositionInternal()
        {
            return Position + _from;
        }
    }
}
