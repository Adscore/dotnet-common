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

namespace AdScore.Signature.Verification.V5
{
    public class Signature5ResponseMapper
    {
        public static Signature5VerificationResult MapToResponse(Dictionary<string, string> result)
        {
            var response = new Signature5VerificationResult();

            var fieldMaps = new (string tupleKey, Action<string> act)[] {
                (tupleKey: "zone_id", act: b => response.SetZoneId(b)),
                (tupleKey: "data", act: b => response.Data = b),
                (tupleKey: "b.tzoffset", act: b => response.SetTzOffset(b)),
                (tupleKey: "HsignatureTime", act: b => response.SignatureTime = b),
                (tupleKey: "b.sr.w", act: b => response.SetHorizontalResolution(b)),
                (tupleKey: "result", act: b => response.SetResult(b)),
                (tupleKey: "b.truech.model", act: b => response.TruechModel = b),
                (tupleKey: "b.truech.platform.v", act: b => response.PlatformV = b),
                (tupleKey: "b.truech.arch", act: b => response.TruechArch = b),
                (tupleKey: "b.platform", act: b => response.SetbPlatform(b)),
                (tupleKey: "b.platform.v", act: b => response.TruechPlatformV = b),
                (tupleKey: "b.gpu", act: b => response.Gpu = b),
                (tupleKey: "b.sr.h", act: b => response.SetVerticalResolution(b)),
                (tupleKey: "b.truech.mobile", act: b => response.TruechMobile = b),
                (tupleKey: "b.cpucores", act: b => response.SetCpuCores(b)),
                (tupleKey: "ipv4.v", act: b => response.SetIpv4V(b)),
                (tupleKey: "ipv6.v", act: b => response.SetIpv6V(b)),
                (tupleKey: "b.truech.bitness", act: b => response.SetTruechBitness(b)),
                (tupleKey: "b.trueloc.c", act: b => response.TrueUaLocation = b),
                (tupleKey: "sub_id", act: b => response.SubId = b),
                (tupleKey: "b.trueua", act: b => response.TrueUa = b),
                (tupleKey: "b.truech.ua", act: b => response.TruechUa = b),
                (tupleKey: "b.ram", act: b => response.SetRam(b)),
                (tupleKey: "requestTime", act: b => response.SetRequestTime(b)),
                (tupleKey: "b.truech.full.v", act: b => response.TruechFullV = b),
                (tupleKey: "ipv4.ip", act: b => response.Ipv4Ip = b),
                (tupleKey: "b.ua", act: b => response.VisitorUserAgent = b),
                (tupleKey: "verdict", act: b => response.Verdict = b),
                (tupleKey: "b.truech.platform", act: b => response.TruechPlatform = b),
                (tupleKey: "signatureTime", act: b => response.SignatureTime = b),
                (tupleKey: "ipv6.ip", act: b => response.Ipv6Ip = b),
                (tupleKey: "token.c", act: b => response.Token = b),
                (tupleKey: "b.applesense", act: b => response.AppleSense = b),
            };

            foreach (var field in fieldMaps)
            {
                var val = result.GetValueOrDefault(field.tupleKey);
                if (val != null)
                {
                    field.act.Invoke(val);
                    result.Remove(field.tupleKey);
                }
            }

            if (result.Any())
            {
                response.AdditionalData = result;
            }

            return response;
        }
    }
}