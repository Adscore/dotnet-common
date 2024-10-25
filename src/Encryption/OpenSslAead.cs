﻿#region License
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
using System.Security.Cryptography;
using AdScore.Signature.ByteOperations;

namespace AdScore.Signature.Encryption
{
    internal class OpenSslAead : CryptParser
    {
        public const int METHOD = 0x0201;

        private readonly CryptMethod cryptMethod = CryptMethod.AES_256_GCM;

        public OpenSslAead() { }

        public override byte[] DecryptWithKey(ByteReader payload, byte[] key)
        {
            var lengths = new Dictionary<string, int>(){
                { "iv", cryptMethod.GetIvLength() },
                { "tag", 16 }
            };

            var parse = Parse(payload, lengths);

            return Decode(parse.Data.Array(),
                    "AES/GCM/NoPadding",
                    key,
                    parse.ByteBufferMap["iv"].Array(),
                    parse.ByteBufferMap["tag"].Array());
        }

        private byte[] Decode(byte[] input, string method, byte[] key, byte[] iv, byte[] tag)
        {
            try
            {
                byte[] output = new byte[input.Length];

                using (var aes = new AesGcm(key))
                {
                    aes.Decrypt(iv, input, tag, output, null);
                }

                return output;
            }
            catch (Exception e)
            {
                throw new ArgumentException("Decryption OpenSSL failed " + e);
            }
        }
    }
}