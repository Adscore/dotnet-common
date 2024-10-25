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
using System.Text;
using AdScore.Signature.ByteOperations;
using AdScore.Signature.Encryption;

namespace AdScore.Signature.Verification.V5
{
    internal class Signature5VerifierService
    {
        private readonly int version = 5;
        private readonly int headerLength = 11;

        public Signature5VerifierService() { }

        public Signature5VerificationResult CreateFromRequest(
                string signature,
                string userAgent,
                string key,
                List<string> ipAddresses)
        {

            var parsed = Parse(signature, SignatureVerifierUtils.Base64Decode(key));
            Verify(parsed, ipAddresses, userAgent);
            return Signature5ResponseMapper.MapToResponse(parsed);
        }


        private Dictionary<string, string> Parse(
                string signature,
                byte[] onCryptKeyRequest)
        {

            var payload = ByteReader.Wrap(SignatureVerifierUtils.Base64Decode(signature));

            if (payload.Capacity <= headerLength)
            {
                throw new ArgumentException("Malformed signature");
            }

            var unpack = PhpUnpack.Unpack("Cversion/nlength/Jzone_id", payload);
            int length = Convert.ToInt32(unpack["length"]);
            long zoneId = (long)unpack["zone_id"];

            if (Convert.ToUInt32(unpack["version"]) != version)
            {
                throw new ArgumentException("Invalid signature version");
            }

            var encryptedPayload = payload.SubBuffer(headerLength, length);

            if (encryptedPayload.Capacity < length)
            {
                throw new ArgumentException("Truncated signature payload");
            }


            var decryptedPayload = DecryptPayload(encryptedPayload, onCryptKeyRequest);
            decryptedPayload["zone_id"] = zoneId.ToString();
            return decryptedPayload;
        }


        private Dictionary<string, string> DecryptPayload(ByteReader payload, byte[] key)
        {
            var crypt = CryptFactory.CreateFromPayload(payload);
            byte[] decryptedPayload = crypt.DecryptWithKey(payload, key);

            var fromPayload = CreateFromPayload(ByteReader.Wrap(decryptedPayload));
            return fromPayload;
        }

        private Dictionary<string, string> CreateFromPayload(ByteReader decryptedPayload)
        {
            string str = Encoding.UTF8.GetString(decryptedPayload.Array());
            string header = SignatureVerifierUtils.Substr(str, 0, 1);
            switch (header)
            {
                case StructUnpacker.SERIALIZE_HEADER:
                case "Serialize":
                case "serialize":
                    return StructUnpacker.SerializeUnpack(decryptedPayload);
                case StructUnpacker.MSG_HEADER:
                case "Msgpack":
                case "msgpack":
                    return StructUnpacker.MsgUnpack(decryptedPayload);
                case StructUnpacker.JSON_HEADER:
                case "StructJson":
                case "json":
                    return StructUnpacker.JsonUnpack(decryptedPayload);
                case StructUnpacker.RFC3986_HEADER:
                case "StructRfc3986":
                case "rfc3986":
                    return StructUnpacker.Rfc3986Unpack(decryptedPayload);
                default:
                    throw new ArgumentException("Unsupported struct class");
            }
        }

        private void Verify(Dictionary<string, string> parsed, List<string> ipAddresses, string userAgent)
        {
            string matchingIp = null;

            foreach (string ipAddress in ipAddresses)
            {
                if (parsed.GetValueOrDefault("ipv4.ip", null) != null)
                {
                    if (ipAddress == parsed["ipv4.ip"])
                    {
                        matchingIp = ipAddress;
                        break;
                    }
                }

                if (parsed.GetValueOrDefault("ipv6.ip", null) != null)
                {
                    if (IpV6Utils.Abbreviate(parsed["ipv6.ip"]) == IpV6Utils.Abbreviate(ipAddress))
                    {
                        matchingIp = ipAddress;
                        break;
                    }
                }
            }

            if (matchingIp == null)
            {
                throw new ArgumentException("Signature IP mismatch");
            }

            if (parsed["b.ua"] != userAgent)
            {
                throw new ArgumentException("Signature user agent mismatch");
            }

            if (SignatureVerifierConstants.Results[parsed["result"]] != parsed["verdict"])
            {
                throw new ArgumentException("Result mismatch");
            }
        }
    }
}