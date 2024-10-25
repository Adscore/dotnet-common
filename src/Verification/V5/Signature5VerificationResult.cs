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

namespace AdScore.Signature.Verification.V5
{
    public class Signature5VerificationResult
    {
        public Signature5VerificationResult() { }
        public string Token { get; set; }
        public long ZoneId { get; private set; }
        public int Result { get; private set; }
        public string Verdict { get; set; }
        public string VisitorUserAgent { get; set; }
        public string Data { get; set; }
        public string Ipv4Ip { get; set; }
        public int Ipv4V { get; private set; }
        public string Ipv6Ip { get; set; }
        public int Ipv6V { get; private set; }
        public int CpuCores { get; private set; }
        public int Ram { get; private set; }
        public int TzOffset { get; private set; }
        public string getbPlatform { get; private set; }
        public string PlatformV { get; set; }
        public string Gpu { get; set; }
        public string AppleSense { get; set; }
        public int HorizontalResolution { get; private set; }
        public int VerticalResolution { get; private set; }
        public string TrueUa { get; set; }
        public string TrueUaLocation { get; set; }
        public int TrueUaLoactionC { get; private set; }
        public string TruechUa { get; set; }
        public string TruechArch { get; set; }
        public int TruechBitness { get; private set; }
        public string TruechModel { get; set; }
        public string TruechPlatformV { get; set; }
        public string TruechPlatform { get; set; }
        public string TruechFullV { get; set; }
        public string TruechMobile { get; set; }
        public string Incognito { get; set; }
        public string SubId { get; set; }
        public long RequestTime { get; private set; }
        public string SignatureTime { get; set; }
        public Dictionary<string, string> AdditionalData { get; set; }

        public void SetZoneId(string zoneId)
        {
            ZoneId = long.Parse(zoneId);
        }

        public void SetRequestTime(string requestTime)
        {
            RequestTime = long.Parse(requestTime);
        }

        public void SetResult(string result)
        {
            Result = int.Parse(result);
        }

        public void SetIpv4V(string ipv4V)
        {
            Ipv4V = int.Parse(ipv4V);
        }

        public void SetIpv6V(string ipv6V)
        {
            Ipv6V = int.Parse(ipv6V);
        }

        public void SetCpuCores(string cpuCores)
        {
            CpuCores = int.Parse(cpuCores);
        }

        public void SetRam(string ram)
        {
            Ram = int.Parse(ram);
        }

        public void SetTzOffset(string tzOffset)
        {
            TzOffset = int.Parse(tzOffset);
        }

        public void SetbPlatform(string bPlatform)
        {
            getbPlatform = bPlatform;
        }

        public void SetHorizontalResolution(string horizontalResolution)
        {
            HorizontalResolution = int.Parse(horizontalResolution);
        }

        public void SetVerticalResolution(string verticalResolution)
        {
            VerticalResolution = int.Parse(verticalResolution);
        }

        public void SetTrueUaLoactionC(string trueUaLoactionC)
        {
            TrueUaLoactionC = int.Parse(trueUaLoactionC);
        }

        public void SetTruechBitness(string truechBitness)
        {
            TruechBitness = int.Parse(truechBitness);
        }
    }
}