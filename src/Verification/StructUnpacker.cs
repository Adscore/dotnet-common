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
using AdScore.Signature.ByteOperations;
using MessagePack;
using Newtonsoft.Json;

namespace AdScore.Signature.Verification
{
    public class StructUnpacker
    {

        public const string SERIALIZE_HEADER = "S";
        public const string JSON_HEADER = "J";
        public const string MSG_HEADER = "M";
        public const string RFC3986_HEADER = "H";

        public static Dictionary<string, string> SerializeUnpack(ByteReader buffer)
        {
            if (GetStringPosition(Encoding.UTF8.GetString(buffer.Array()), SERIALIZE_HEADER, 0) != 0)
            {
                throw new ArgumentException("Unexpected serializer type");
            }
            try
            {
                string payload = Encoding.UTF8.GetString(buffer.SubBuffer(SERIALIZE_HEADER.Length).Array());
                var v = (Dictionary<object, object>)new PhpDeserializer(payload).Unserialize();
                return v.ToDictionary(x => x.Key.ToString(), x => x.Value.ToString());
            }
            catch (Exception e)
            {
                throw new ArgumentException("Error parsing Serialize struct: " + e);
            }
        }

        public static Dictionary<string, string> JsonUnpack(ByteReader payload)
        {
            try
            {
                string strPayload = Encoding.UTF8.GetString(payload.Array());
                string substring = strPayload.Substring(1, strPayload.Length - 1);
                return JsonConvert.DeserializeObject<Dictionary<string, string>>(substring);
            }
            catch (JsonException e)
            {
                throw new ArgumentException("Error parsing StructJson struct: " + e);
            }
        }

        public static Dictionary<string, string> MsgUnpack(ByteReader buffer)
        {
            try
            {
                buffer.Position = 1;
                var slice = buffer.Slice();
                string json = MessagePackSerializer.ConvertToJson(slice.Array());
                return JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }
            catch (Exception e)
            {
                throw new ArgumentException("Error parsing MsgPack struct: " + e);
            }
        }

        public static Dictionary<string, string> Rfc3986Unpack(ByteReader data)
        {
            try
            {
                string queryString = Encoding.UTF8.GetString(data.Array());
                string decoded = decodeUrl(queryString);
                string[] pairs = decoded.Split("&");
                var result = new Dictionary<string, string>();

                foreach (string pair in pairs)
                {
                    string[] keyValue = pair.Split("=", 2);
                    if (keyValue.Length == 2)
                    {
                        result[keyValue[0]] = keyValue[1];
                    }
                    else
                    {
                        result[keyValue[0]] = "";
                    }
                }
                return result;
            }
            catch (Exception e)
            {
                throw new ArgumentException("Error parsing StructRfc3986 struct: " + e);
            }
        }

        private static string decodeUrl(string encodedUrl)
        {
            var decodedUrl = new StringBuilder();
            int len = encodedUrl.Length;
            int i = 0;

            while (i < len)
            {
                char c = encodedUrl[i];
                if (c == '%')
                {
                    if (i + 2 < len)
                    {
                        string hex = encodedUrl.Substring(i + 1, 2);
                        try
                        {
                            char decodedChar = (char)Convert.ToInt16(hex, 16);
                            var unused3 = decodedUrl.Append(decodedChar);
                            i += 3;
                        }
                        catch (FormatException)
                        {
                            _ = decodedUrl.Append(c);
                            i++;
                        }
                    }
                    else
                    {
                        _ = decodedUrl.Append(c);
                        i++;
                    }
                }
                else
                {
                    _ = decodedUrl.Append(c);
                    i++;
                }
            }

            return decodedUrl.ToString();
        }

        private static int GetStringPosition(string input, string searchFor, int offset)
        {
            if (input == null || searchFor == null)
            {
                return -1;
            }
            return input.IndexOf(searchFor, offset);
        }
    }
}
