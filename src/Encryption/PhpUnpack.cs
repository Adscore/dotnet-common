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
using AdScore.Signature.ByteOperations;

namespace AdScore.Signature.Encryption
{
    public class PhpUnpack
    {
        private static readonly string NAME = "name";
        private static readonly string CODE = "code";

        public static Dictionary<string, object> Unpack(string format, ByteReader input)
        {
            string[] instructions = format.Split("/");

            var result = new Dictionary<string, object>();

            foreach (string instruction in instructions)
            {
                var codeAndName = GetCodeAndName(instruction);

                string code = codeAndName[CODE];
                string name = codeAndName[NAME];

                var decodedData = Decode(input, code);
                result[name] = decodedData.GetDecodedData();
            }
            return result;
        }

        private static DecodedData Decode(ByteReader input, string code)
        {
            object decodedData;
            if (!input.HasRemaining())
            {
                throw new ArgumentException("Buffer underflow. No more data to read.");
            }
            int bytesOffset;

            switch (code)
            {
                case "c":
                    decodedData = input.Get();
                    bytesOffset = 1;
                    break;
                case "C":
                    decodedData = input.Get();// & 0xFF;
                    bytesOffset = 1;
                    break;
                case "n":
                    decodedData = input.GetShort();
                    bytesOffset = 2;
                    break;
                case "N":
                    decodedData = input.GetInt();
                    bytesOffset = 4;
                    break;
                case "J":
                    decodedData = input.GetLong();
                    bytesOffset = 8;
                    break;
                case "v":
                    decodedData = input.Order(ByteOrder.LITTLE_ENDIAN).GetShort();
                    input.Order(ByteOrder.BIG_ENDIAN);
                    bytesOffset = 2;
                    break;
                default:
                    throw new ArgumentException("Unrecognized instruction: " + code);
            }
            return new DecodedData(bytesOffset, decodedData);
        }

        public static byte[] Pack(string format, params object[] inputs)
        {
            string[] instructions = format.Split("");

            if (instructions.Length != inputs.Length)
            {
                throw new ArgumentException(
                        "Invalid format length, expected " + inputs.Length + " number of codes"
                );
            }

            var result = ByteWriter.Allocate(1024).Order(ByteOrder.BIG_ENDIAN);

            for (int i = 0; i < inputs.Length; i++)
            {
                string code = instructions[i];
                var encodedData = Encode(inputs[i], code);
                result.Put(encodedData);
            }

            return result.Array();
        }

        private static byte[] Encode(object input, string code)
        {
            ByteWriter buffer;
            switch (code)
            {
                case "c":
                    buffer = ByteWriter.Allocate(1);
                    buffer.Put(Convert.ToByte(input));
                    break;
                case "C":
                    buffer = ByteWriter.Allocate(1);
                    buffer.Put((byte)(Convert.ToByte(input) & 0xFF));
                    break;
                case "n":
                    buffer = ByteWriter.Allocate(2).Order(ByteOrder.BIG_ENDIAN);
                    buffer.PutShort(Convert.ToInt16(input));
                    break;
                case "N":
                    buffer = ByteWriter.Allocate(4).Order(ByteOrder.BIG_ENDIAN);
                    buffer.PutInt(Convert.ToInt32(input));
                    break;
                case "J":
                    buffer = ByteWriter.Allocate(8).Order(ByteOrder.BIG_ENDIAN);
                    buffer.PutLong(Convert.ToInt64(input));
                    break;
                case "v":
                    buffer = ByteWriter.Allocate(2).Order(ByteOrder.LITTLE_ENDIAN);
                    buffer.PutShort(Convert.ToInt16(input));
                    break;
                default:
                    throw new ArgumentException("Unrecognized instruction: " + code);
            }

            return buffer.Array();
        }

        private static Dictionary<string, string> GetCodeAndName(string instruction)
        {
            if (instruction == null || instruction.Length == 0)
            {
                throw new ArgumentException("Empty instruction");
            }

            var result = new Dictionary<string, string>
            {
                [CODE] = instruction.Substring(0, 1),
                [NAME] = instruction.Substring(1)
            };
            return result;
        }
    }
}
