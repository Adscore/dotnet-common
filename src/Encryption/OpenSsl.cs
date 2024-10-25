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
using System.IO;
using System.Security.Cryptography;
using AdScore.Signature.ByteOperations;

namespace AdScore.Signature.Encryption
{
    internal class OpenSsl : CryptParser
    {
        public const int METHOD = 0x0200;

        private readonly CryptMethod cryptMethod = CryptMethod.AES_256_CBC;

        public OpenSsl() { }

        public override byte[] DecryptWithKey(ByteReader payload, byte[] key)
        {
            var lengths = new Dictionary<string, int>() { { "iv", cryptMethod.GetIvLength() } };
            var result = Parse(payload, lengths);

            if (result.Method != METHOD)
            {
                throw new ArgumentException("Unrecognized payload");
            }

            byte[] decoded = Decode(result.Data.Array(), "AES/CBC/PKCS5Padding", key, result.ByteBufferMap["iv"].Array());
            return decoded;
        }

        private byte[] Decode(byte[] input, string method, byte[] key, byte[] iv)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using var ms = new MemoryStream(input);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var br = new BinaryReader(cs);
                return br.ReadBytes((int)ms.Length);
            }
            catch (Exception e)
            {
                throw new ArgumentException("Decryption OpenSSL failed " + e);
            }
        }
    }
}