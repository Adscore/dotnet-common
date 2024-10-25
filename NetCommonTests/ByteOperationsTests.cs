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

using AdScore.Signature.ByteOperations;

namespace Adscore.Signature.Tests
{
    public class ByteOperationsTests
    {
        [Test]
        public void Get()
        {
            var stream = new MemoryStream();
            byte[] arr = null;
            using (var reader = new BinaryWriter(stream))
            {
                reader.Write((byte)0);
                reader.Write((short)1);
                reader.Write((int)2);
                reader.Write((long)3);
                arr = stream.ToArray();
            }

            var buffer = ByteReader.Wrap(arr).Order(ByteOrder.LITTLE_ENDIAN);
            byte b = buffer.Get();
            Assert.That(b, Is.EqualTo(0));

            short s = buffer.GetShort();
            Assert.That(s, Is.EqualTo(1));

            int i = buffer.GetInt();
            Assert.That(i, Is.EqualTo(2));

            long l = buffer.GetLong();
            Assert.That(l, Is.EqualTo(3));
        }

        [Test]
        public void Slice()
        {
            byte[] bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            var buffer = ByteReader.Wrap(bytes).Order(ByteOrder.LITTLE_ENDIAN);
            buffer.Get(); // skip 0

            var sub1 = buffer.Slice();
            var subFirstByte = sub1.Get();
            Assert.That(subFirstByte, Is.EqualTo(1));

            var origNextByte = buffer.Get();
            Assert.That(origNextByte, Is.EqualTo(1));
        }

        [Test]
        public void SubBuffer()
        {
            byte[] bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            var buffer = ByteReader.Wrap(bytes).Order(ByteOrder.LITTLE_ENDIAN);
            buffer.Get();

            var sub1 = buffer.SubBuffer(2);
            var subFirstByte = sub1.Get();
            Assert.That(subFirstByte, Is.EqualTo(2));

            var origNextByte = buffer.Get();
            Assert.That(origNextByte, Is.EqualTo(1));
        }

        [Test]
        public void Position()
        {
            byte[] bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            var buffer = ByteReader.Wrap(bytes).Order(ByteOrder.LITTLE_ENDIAN);
            buffer.Get();
            buffer.Position -= 1;

            var nextByte = buffer.Get();
            Assert.That(nextByte, Is.EqualTo(0));
        }

        [Test]
        public void Flip()
        {
            byte[] bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            var buffer = ByteReader.Wrap(bytes).Order(ByteOrder.LITTLE_ENDIAN);
            buffer.Get();
            buffer.Get();

            var arr = buffer.Array();

            Assert.That(arr[0], Is.EqualTo(0));
        }
    }
}
