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
using System.Text;
using AdScore.Signature.Exceptions;

namespace AdScore.Signature.Verification.V4
{
    public class Signature4VerifierService
    {
        private static readonly Dictionary<int, Field> _fieldIds = new Dictionary<int, Field>() {
          {0x00, new Field("requestTime", "ulong")},
          {0x01, new Field("signatureTime", "ulong")},
          {0x40, new Field(null, "ushort")},
          {0x80, new Field("masterSignType", "uchar")},
          {0x81, new Field("customerSignType", "uchar")},
          {0xC0, new Field("masterToken", "string")},
          {0xC1, new Field("customerToken", "string")},
          {0xC2, new Field("masterTokenV6", "string")},
          {0xC3, new Field("customerTokenV6", "string")}
        };

        internal Signature4VerificationResult VerifySignature(
            string signature,
            string userAgent,
            string signRole,
            string key,
            bool isKeyBase64Encoded,
            int? expiry,
            string[] ipAddresses)
        {
            var validationResult = new Signature4VerificationResult();

            try
            {
                Dictionary<string, object> data;
                try
                {
                    data = Parse4(signature);
                }
                catch (BaseSignatureVerificationException exp)
                {
                    if (exp is SignatureRangeException)
                    {
                        data = Parse3(signature);
                    }
                    else
                    {
                        validationResult.Error = exp.Message;
                        return validationResult;
                    }
                }

                bool unused = data.TryGetValue(signRole + "Token", out object signRoleTokenObj);
                string signRoleToken = (string)signRoleTokenObj;

                if (signRoleToken == null || signRoleToken.Length == 0)
                {

                    validationResult.Error = "sign role signature mismatch";
                    return validationResult;
                }

                int signType = (int)data[signRole + "SignType"];

                foreach (string ipAddress in ipAddresses)
                {
                    string currentIpAddress = ipAddress;
                    string token;
                    if (currentIpAddress == null || currentIpAddress.Length == 0)
                    {
                        continue;
                    }
                    if (IpV6Utils.Validate(currentIpAddress))
                    {
                        if (!data.ContainsKey(signRole + "TokenV6"))
                        {
                            continue;
                        }
                        token = (string)data[signRole + "TokenV6"];
                        currentIpAddress = IpV6Utils.Abbreviate(currentIpAddress);
                    }
                    else
                    {
                        if (!data.ContainsKey(signRole + "Token"))
                        {
                            continue;
                        }

                        token = (string)data[signRole + "Token"];
                    }

                    int signatureTime = (int)data["signatureTime"];
                    int requestTime = (int)data["requestTime"];

                    foreach (string result in SignatureVerifierConstants.Results.Keys)
                    {
                        bool isValid = false;
                        string signatureBase = GetBase(result, requestTime, signatureTime, currentIpAddress, userAgent);
                        switch (signType)
                        {
                            case 1://HASH_SHA256
                                string decodedKey = isKeyBase64Encoded ? SignatureVerifierUtils.KeyDecode(key) : key;
                                bool isHashedDataEqualToToken = SignatureVerifierUtils.CompareBytes(SignatureVerifierUtils.Encode(decodedKey, signatureBase), token);

                                if (isHashedDataEqualToToken)
                                {
                                    if (IsExpired(expiry, signatureTime, requestTime))
                                    {
                                        validationResult.Expired = true;
                                        return validationResult;
                                    }
                                    isValid = true;
                                    break;
                                }
                                break;
                            case 2://SIGN_SHA256
                                if (VerifyData(signatureBase, token, key, isKeyBase64Encoded, "SHA256withECDSA"))
                                {
                                    isValid = true;
                                    break;
                                }
                                break;
                            default:
                                validationResult.Error = "unrecognized signature";
                                return validationResult;
                        }

                        if (isValid)
                        {
                            validationResult.Score = int.Parse(result);
                            validationResult.Verdict = SignatureVerifierConstants.Results[result];
                            validationResult.IpAddress = ipAddress;
                            validationResult.RequestTime = (int)data["requestTime"];
                            validationResult.SignatureTime = (int)data["signatureTime"];

                            return validationResult;
                        }
                    }
                }

                validationResult.Error = "no verdict";
                return validationResult;

            }
            catch (Exception exp)
            {
                string base64Exception = "The input is not a valid Base-64 string";

                if (exp.Message.StartsWith(base64Exception))
                {
                    validationResult.Error = exp.Message.Replace(base64Exception, "Key/Signature is not a valid Base-64 string");
                    return validationResult;
                }
                else
                {
                    validationResult.Error = exp.Message;
                    return validationResult;
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="expiry">expiry how long request and signature are valid (in seconds)</param>
        /// <param name="signatureTime">signatureTime epoch time in seconds</param>
        /// <param name="requestTime">requestTime epoch time in seconds</param>
        /// <returns>false if expiry is null. True if either signatureTime or requestTime expired, false otherwise.</returns>
        /// <exception cref="SignatureVerificationException"></exception>
        public bool IsExpired(int? expiry, int signatureTime, int requestTime)
        {
            if (expiry == null)
            {
                // If expiry time not provided, neither signatureTime nor requestTime can be expired.
                return false;
            }

            long currentEpochInSeconds = SignatureVerifierUtils.UnixTimestamp / 1000;

            // Cast both times to long, because operating on int epoch seconds exceeds integer max value
            // while adding higher dates (around 2035)
            bool isSignatureTimeExpired = signatureTime + (long)expiry < currentEpochInSeconds;
            bool isRequestTimeExpired = requestTime + (long)expiry < currentEpochInSeconds;

            return isSignatureTimeExpired || isRequestTimeExpired;
        }

        public string GetBase(
            string verdict, int requestTime, int signatureTime, string ipAddress, string userAgent)
        {
            var builder = new StringBuilder();

            return builder
                .Append(verdict)
                .Append("\n")
                .Append(requestTime.ToString())
                .Append("\n")
                .Append(signatureTime.ToString())
                .Append("\n")
                .Append(ipAddress)
                .Append("\n")
                .Append(userAgent)
                .ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="BaseSignatureVerificationException"></exception>
        private Dictionary<string, object> Parse3(string signature)
        {
            signature = SignatureVerifierUtils.FromBase64(signature);
            if (!"".Equals(signature))
            {
                throw new SignatureVerificationException("invalid base64 payload");
            }

            var unpackResult =
                Unpacker.Unpack(
                    "Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength", signature);

            int version = (int)unpackResult.Data["version"];

            if (version != 3)
            {
                throw new SignatureRangeException("unsupported version");
            }

            long timestamp = (long)unpackResult.Data["timestamp"];
            if (timestamp > SignatureVerifierUtils.UnixTimestamp / 1000)
            {
                throw new SignatureVerificationException("invalid timestamp (future time)");
            }

            int masterTokenLength = (int)unpackResult.Data["masterTokenLength"];
            string masterToken = SignatureVerifierUtils.Substr(signature, 12, masterTokenLength + 12);
            unpackResult.Data.Add("masterToken", masterToken);

            int s1, s2;

            if ((s1 = masterTokenLength) != (s2 = masterToken.Length))
            {
                throw new SignatureVerificationException(
                    string.Format("master token length mismatch ({0} / {1})", s1, s2));
            }

            signature = SignatureVerifierUtils.Substr(signature, masterTokenLength + 12);

            var data2 = Unpacker.Unpack("CcustomerSignType/ncustomerTokenLength", signature).Data;

            int customerTokenLength = (int)data2["customerTokenLength"];
            string customerToken = SignatureVerifierUtils.Substr(signature, 3, customerTokenLength + 3);
            data2.Add("customerToken", customerToken);

            if ((s1 = customerTokenLength) != (s2 = customerToken.Length))
            {
                throw new SignatureVerificationException(
                    string.Format("customer token length mismatch ({0} / {1})')", s1, s2));
            }

            return unpackResult.Data.Union(data2).ToDictionary(k => k.Key, v => v.Value);
        }

        private Field FieldTypeDef(int fieldId, int i)
        {
            if (_fieldIds.TryGetValue(fieldId, out var value))
            {
                return value;
            }

            string resultType = _fieldIds[fieldId & 0xC0].Type;

            string iStr = SignatureVerifierUtils.PadStart(i.ToString(), 2, '0');
            string resultName = resultType + iStr;

            return new Field(resultName, resultType);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="BaseSignatureVerificationException"></exception>
        private Dictionary<string, object> Parse4(string signature)

        {
            signature = SignatureVerifierUtils.FromBase64(signature);

            if (signature.Length == 0)
            {
                throw new SignatureVerificationException("invalid base64 payload");
            }

            var data = Unpacker.Unpack("Cversion/CfieldNum", signature).Data;

            int version = (int)data["version"];
            if (version != 4)
            {
                throw new SignatureRangeException("unsupported version");
            }
            signature = SignatureVerifierUtils.Substr(signature, 2);

            int fieldNum = (int)data["fieldNum"];

            for (int i = 0; i < fieldNum; ++i)
            {
                var header = Unpacker.Unpack("CfieldId", signature).Data;

                if (header.Count == 0 || !header.ContainsKey("fieldId")) // header.entrySet().size() ???
                {
                    throw new SignatureVerificationException("premature end of signature 0x01");
                }

                var fieldTypeDef = FieldTypeDef((int)header["fieldId"], i);
                var v = new Dictionary<string, object>();
                Dictionary<string, object> l;

                switch (fieldTypeDef.Type)
                {
                    case "uchar":
                        v = Unpacker.Unpack("Cx/Cv", signature).Data;
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new SignatureVerificationException("premature end of signature 0x02");
                        }
                        signature = SignatureVerifierUtils.Substr(signature, 2);
                        break;
                    case "ushort":
                        v = Unpacker.Unpack("Cx/nv", signature).Data;
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new Exception("premature end of signature 0x03");
                        }
                        signature = SignatureVerifierUtils.Substr(signature, 3);
                        break;
                    case "ulong":
                        v = Unpacker.Unpack("Cx/Nv", signature).Data;
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new Exception("premature end of signature 0x04");
                        }
                        signature = SignatureVerifierUtils.Substr(signature, 5);
                        break;
                    case "string":
                        l = Unpacker.Unpack("Cx/nl", signature).Data;
                        if (!l.ContainsKey("l"))
                        {
                            throw new Exception("premature end of signature 0x05");
                        }
                        if (((int)l["l"] & 0x8000) > 0)
                        {
                            int newl = (int)l["l"] & 0xFF;
                            l.Add("l", newl);
                        }

                        string newV = SignatureVerifierUtils.Substr(signature, 3, (int)l["l"]);
                        v.Add("v", newV);
                        data.Add(fieldTypeDef.Name, newV);

                        if (((string)v["v"]).Length != (int)l["l"])
                        {
                            throw new SignatureVerificationException("premature end of signature 0x06");
                        }

                        signature = SignatureVerifierUtils.Substr(signature, 3 + (int)l["l"]);

                        break;
                    default:
                        throw new SignatureVerificationException("unsupported variable type");
                }
            }

            _ = data.Remove(fieldNum.ToString());
            return data;
        }

        private bool VerifyData(string signatureBase, string token, string key, bool isKeyBase64Encoded, string algorithm)
        {
            var crypt = new EcdsaVerifier(algorithm);

            if (key.Contains("BEGIN"))
            {
                key = key.Replace("-----BEGIN PUBLIC KEY-----", "")
                        .Replace("-----END PUBLIC KEY-----", "")
                        .Replace("\\s", "");
            }

            var enc = Encoding.UTF8; // TODO ???
            byte[] keyBytes = isKeyBase64Encoded ? Convert.FromBase64String(key) : enc.GetBytes(key);
            if (crypt.Verify(signatureBase, token, keyBytes))
            {
                throw new Exception("Signature verification error");
            }

            return true;
        }
    }
}
