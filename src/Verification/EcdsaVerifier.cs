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
using System.Security.Cryptography;
using System.Text;

namespace AdScore.Signature.Verification
{
    class EcdsaVerifier
    {
        private const string Base64Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/=";
        private readonly string algorithm;

        public EcdsaVerifier(string algorithm)
        {
            this.algorithm = algorithm;
        }

        public bool Verify(string data, string token, byte[] publicKey)
        {
            try
            {
                using ECDsa ecdsa = ECDsa.Create();

                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);

                ECParameters parameters = ecdsa.ExportParameters(false);
                byte[] decodedData = GetBytesBase64Mime(data);
                byte[] signInputBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(token);

                HashAlgorithmName hashAlgorithm;
                switch (algorithm.ToUpper())
                {
                    case "SHA256":
                    case "SHA256WITHECDSA":
                        hashAlgorithm = HashAlgorithmName.SHA256;
                        break;
                    case "SHA384":
                        hashAlgorithm = HashAlgorithmName.SHA384;
                        break;
                    case "SHA512":
                        hashAlgorithm = HashAlgorithmName.SHA512;
                        break;
                    default:
                        throw new CryptographicException("Unsupported algorithm: " + algorithm);
                }

                return ecdsa.VerifyData(decodedData, signInputBytes, hashAlgorithm);
            }
            catch (CryptographicException e)
            {
                throw new Exception("Signature verification error: " + e.Message);
            }
            catch (ArgumentException e)
            {
                throw new Exception("Invalid argument: " + e.Message);
            }
            catch (Exception e)
            {
                throw new Exception("Unexpected error: " + e.Message);
            }
        }

        private static string StripNonBase64Characters(string input)
        {
            string stripped = new string(input.Where(c => Base64Characters.Contains(c)).ToArray());
            int mod4 = stripped.Length % 4;

            if (mod4 > 0)
            {
                stripped += new string('=', 4 - mod4);
            }

            return stripped;
        }

        private static byte[] GetBytesBase64Mime(string origBase64String)
        {
            var base64String = StripNonBase64Characters(origBase64String);

            // Split the string into lines of 76 characters
            string formattedBase64 = string.Empty;
            int lineLength = 76;
            for (int i = 0; i < base64String.Length; i += lineLength)
            {
                // If the last segment is less than 76 characters, just take the rest of the string
                if (i + lineLength < base64String.Length)
                {
                    formattedBase64 += base64String.Substring(i, lineLength) + Environment.NewLine;
                }
                else
                {
                    formattedBase64 += base64String.Substring(i) + Environment.NewLine;
                }
            }
            var trimmed = formattedBase64.Trim(); // Trim to remove the last newline

            return Convert.FromBase64String(trimmed);
        }
    }
}
