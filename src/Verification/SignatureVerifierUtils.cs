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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AdScore.Signature.Exceptions;
using AdScore.Signature.Extensions;
using AdScore.Signature.Helpers;

[assembly: InternalsVisibleTo("AdscoreClientNetLibs.Signature.Tests")]
namespace AdScore.Signature.Verification
{
    public class SignatureVerifierUtils
    {
        internal static long UnixTimestamp => Convert.ToInt64(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds);

        internal static string Substr(string str, int startIdx, int length)
        {
            if (startIdx > str.Length)
            {
                return "";
            }

            length = length.Clamp(0, str.Length - startIdx);

            return str.Substring(startIdx, length);
        }

        internal static string Substr(string str, int length)
        {
            return Substr(str, length, str.Length);
        }

        internal static char CharAt(string str, int idx)
        {
            if (idx < 0 || idx >= str.Length)
            {
                return (char)0;
            }

            return str[idx];
        }

        public static string Encode(string key, string data)
        {
            var encoding = Encoding.GetEncoding("ISO-8859-1");

            byte[] textBytes = encoding.GetBytes(data);
            byte[] keyBytes = encoding.GetBytes(key);

            byte[] hashBytes;

            using (var hash = new HMACSHA256(keyBytes))
            {
                hashBytes = hash.ComputeHash(textBytes);
            }

            return encoding.GetString(hashBytes);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">in base64 format</param>
        /// <returns>decoded key</returns>
        public static string KeyDecode(string key)
        {
            return Atob(key);
        }

        public static string Atob(string str)
        {
            byte[] isoBytes = Convert.FromBase64String(str);
            byte[] utf8Bytes = Encoding.Convert(Encoding.GetEncoding("iso-8859-1"), Encoding.UTF8, isoBytes);
            return Encoding.UTF8.GetString(utf8Bytes, 0, utf8Bytes.Length);
        }

        public static string PadStart(string inputstring, int length, char c)
        {
            if (inputstring.Length >= length)
            {
                return inputstring;
            }
            var sb = new StringBuilder();
            while (sb.Length < length - inputstring.Length)
            {
                sb.Append(c);
            }
            sb.Append(inputstring);

            return sb.ToString();
        }

        internal static string FromBase64(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                throw new SignatureVerificationException("empty key or signature");
            }

            int mod4 = data.Length % 4;
            if (mod4 > 0)
            {
                data += new string('=', 4 - mod4);
            }

            return Atob(data.Replace('_', '/').Replace('-', '+'));
        }

        internal static bool IsCharMatches(string regex, int formatChar)
        {
            var matches = Regex.Matches(formatChar.ToString(), regex);
            return matches.Count > 0;
        }

        internal static bool CompareBytes(string first, string second)
        {
            return ByteArrayHelper.Compare(first.ToIso88591EncodingByteArray(), second.ToIso88591EncodingByteArray());
        }

        public static byte[] Base64Decode(string base64Input)
        {
            int mod4 = base64Input.Length % 4;
            if (mod4 > 0)
            {
                base64Input += new string('=', 4 - mod4);
            }

            if (base64Input.Contains("-") || base64Input.Contains("_"))
            {

                base64Input = base64Input.Replace('_', '/').Replace('-', '+');
                byte[] isoBytes = Convert.FromBase64String(base64Input);
                return isoBytes;
            }

            return Convert.FromBase64String(base64Input);
        }
    }
}