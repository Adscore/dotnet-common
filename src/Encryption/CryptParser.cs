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
using System.Collections.Generic;
using System.Linq;
using AdScore.Signature.ByteOperations;

namespace AdScore.Signature.Encryption
{
    internal abstract class CryptParser
    {
        private readonly int methodSize = 2;

        public abstract byte[] DecryptWithKey(ByteReader payload, byte[] key);

        protected DecryptResult Parse(ByteReader payload, Dictionary<string, int> lengths)
        {
            if (payload.Capacity < methodSize + lengths.Values.Aggregate(0, (a, b) => a + b))
            {
                throw new InvalidOperationException("Premature data end");
            }

            int pos = methodSize;
            var decryptResult = new DecryptResult();
            var unpack = PhpUnpack.Unpack("vmethod", payload.SubBuffer(0, pos));
            decryptResult.            Method = Convert.ToInt32(unpack["method"]);

            foreach (var entry in lengths)
            {
                var bytesForKey = payload.SubBuffer(pos, entry.Value);
                decryptResult.                ByteBufferMap[entry.Key] = bytesForKey;
                pos += entry.Value;
            }

            decryptResult.
            Data = payload.SubBuffer(pos, null);
            return decryptResult;
        }
    }
}
