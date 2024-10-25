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

namespace AdScore.Signature.Verification
{
    public class PhpDeserializer
    {
        private readonly string data;
        private int index;

        public PhpDeserializer(string data)
        {
            this.data = data;
            index = 0;
        }

        public object Unserialize()
        {
            char type = data[index];
            index += 2;

            switch (type)
            {
                case 'i':
                    return ParseInt();
                case 'd':
                    return ParseFloat();
                case 'b':
                    return ParseBoolean();
                case 's':
                    return ParseString();
                case 'a':
                    return ParseArray();
                case 'O':
                    return ParseObject();
                default:
                    throw new ArgumentException("PhpUnserializer error. Unsupported type: " + type);
            }
        }

        private string ParseInt()
        {
            int semiColonIndex = data.IndexOf(';', index);
            string intStr = data.Substring(index, semiColonIndex - index);
            index = semiColonIndex + 1;
            return intStr;
        }

        private string ParseFloat()
        {
            int semiColonIndex = data.IndexOf(';', index);
            string floatStr = data.Substring(index, semiColonIndex - index);
            index = semiColonIndex + 1;
            return floatStr;
        }

        private string ParseBoolean()
        {
            char boolChar = data[index];
            index += 2;
            return boolChar == '1' ? "true" : "false";
        }

        private string ParseString()
        {
            int colonIndex = data.IndexOf(':', index);
            int length = int.Parse(data.Substring(index, colonIndex - index));
            index = colonIndex + 2;
            string str = data.Substring(index, length);
            index += length + 2;
            return str;
        }

        private Dictionary<object, object> ParseArray()
        {
            int colonIndex = data.IndexOf(':', index);
            int length = int.Parse(data.Substring(index, colonIndex - index));
            index = colonIndex + 2;
            var map = new Dictionary<object, object>();
            for (int i = 0; i < length; i++)
            {
                object key = Unserialize();
                object value = Unserialize();
                map[key] = value;
            }
            index++;
            return map;
        }

        private Dictionary<string, object> ParseObject()
        {
            int colonIndex = data.IndexOf(':', index);
            int classNameLength = int.Parse(data.Substring(index, colonIndex - index));
            index = colonIndex + 2;
            data.Substring(index, classNameLength);
            index += classNameLength + 2;

            colonIndex = data.IndexOf(':', index);
            int length = int.Parse(data.Substring(index, colonIndex - index));
            index = colonIndex + 2;
            var fields = new Dictionary<string, object>();
            for (int i = 0; i < length; i++)
            {
                string key = (string)Unserialize();
                object value = Unserialize();
                fields[key] = value;
            }
            index++;

            return fields;
        }
    }
}
