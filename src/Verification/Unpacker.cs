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

using System.Collections.Generic;
using System.Text;

namespace AdScore.Signature.Verification
{
    internal static class Unpacker
    {
        /// <summary>
        /// Unpacks data from a binary string into the respective format.
        /// </summary>
        /// <param name="format">fields that have to be unpacked from data, forward slash separated.</param>
        /// <param name="data">Binary string, already decoded from Base64</param>
        /// <returns>object which contains unpacked data as a hash map, where key is a name of
        ///          the field. if result contains non-null error message then it means that unpacking failed.
        ///          Data hash map is null then.</returns>
        /// <exception cref="SignatureVerificationException"></exception>
        internal static UnpackResult Unpack(string format, string data)
        {
            int formatPointer = 0;
            int dataPointer = 0;
            var resultMap = new Dictionary<string, object>();
            int instruction;
            string quantifier;
            int quantifierInt;
            string label;
            string currentData;
            int i;
            int currentResult;

            while (formatPointer < format.Length)
            {
                instruction = SignatureVerifierUtils.CharAt(format, formatPointer);
                quantifier = "";
                formatPointer++;

                while (formatPointer < format.Length
                    && SignatureVerifierUtils.IsCharMatches(@"\A(?:[\\d\\*])\z", SignatureVerifierUtils.CharAt(format, formatPointer)))
                {
                    quantifier += SignatureVerifierUtils.CharAt(format, formatPointer);
                    formatPointer++;
                }
                if (string.IsNullOrEmpty(quantifier))
                {
                    quantifier = "1";
                }

                var labelSb = new StringBuilder();
                while (formatPointer < format.Length && format[formatPointer] != '/')
                {
                    labelSb.Append(SignatureVerifierUtils.CharAt(format, formatPointer++));
                }
                label = labelSb.ToString();

                if (SignatureVerifierUtils.CharAt(format, formatPointer) == '/')
                {
                    formatPointer++;
                }

                switch (instruction)
                {
                    case 'c':
                    case 'C':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = data.Length - dataPointer;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = SignatureVerifierUtils.Substr(data, dataPointer, quantifierInt);
                        dataPointer += quantifierInt;

                        for (i = 0; i < currentData.Length; i++)
                        {
                            currentResult = SignatureVerifierUtils.CharAt(currentData, i);

                            if (instruction == 'c' && currentResult >= 128)
                            {
                                currentResult -= 256;
                            }

                            string key = label + (quantifierInt > 1 ? (i + 1).ToString() : "");
                            resultMap.Add(key, currentResult);
                        }
                        break;
                    case 'n':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = (data.Length - dataPointer) / 2;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = SignatureVerifierUtils.Substr(data, dataPointer, quantifierInt * 2);
                        dataPointer += quantifierInt * 2;
                        for (i = 0; i < currentData.Length; i += 2)
                        {
                            currentResult =
                                ((SignatureVerifierUtils.CharAt(currentData, i) & 0xFF) << 8)
                                    + (SignatureVerifierUtils.CharAt(currentData, i + 1) & 0xFF);

                            string key = label + (quantifierInt > 1 ? (i / 2 + 1).ToString() : "");
                            resultMap.Add(key, currentResult);
                        }
                        break;
                    case 'N':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = (data.Length - dataPointer) / 4;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = SignatureVerifierUtils.Substr(data, dataPointer, quantifierInt * 4);
                        dataPointer += quantifierInt * 4;
                        for (i = 0; i < currentData.Length; i += 4)
                        {
                            currentResult =
                                ((SignatureVerifierUtils.CharAt(currentData, i) & 0xFF) << 24)
                                    + ((SignatureVerifierUtils.CharAt(currentData, i + 1) & 0xFF) << 16)
                                    + ((SignatureVerifierUtils.CharAt(currentData, i + 2) & 0xFF) << 8)
                                    + (SignatureVerifierUtils.CharAt(currentData, i + 3) & 0xFF);

                            string key = label + (quantifierInt > 1 ? (i / 4 + 1).ToString() : "");
                            resultMap.Add(key, currentResult);
                        }
                        break;
                    default:
                        return new UnpackResult(string.Format("Unknown format code: {0}", instruction.ToString()));
                }
            }

            return new UnpackResult(resultMap); ;
        }

    }
}
