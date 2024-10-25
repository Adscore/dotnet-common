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

using AdScore.Signature.Verification;

namespace NetCommonTests
{
    public class IpV6Tests
    {
        [Test]
        public void ValidateProperIpV6Address()
        {
            Assert.True(IpV6Utils.Validate("2405:3800:85a:9e80:47d2:1d4c:5604:37f0"));
            Assert.True(IpV6Utils.Validate("0:0:0:0:0:ffff:4d73:55d3"));
            Assert.True(IpV6Utils.Validate("1080::8:800:200c:417a"));

            Assert.True(IpV6Utils.Validate("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789"));
            Assert.True(IpV6Utils.Validate("2001:DB8:0:0:8:800:200C:417A"));
            Assert.True(IpV6Utils.Validate("FF01:0:0:0:0:0:0:101"));
            Assert.True(IpV6Utils.Validate("0:0:0:0:0:0:0:1"));
            Assert.True(IpV6Utils.Validate("0:0:0:0:0:0:0:0"));

            Assert.True(IpV6Utils.Validate("2001:DB8::8:800:200C:417A"));
            Assert.True(IpV6Utils.Validate("FF01::101"));
            Assert.True(IpV6Utils.Validate("::1"));

            Assert.True(IpV6Utils.Validate("0:0:0:0:0:0:13.1.68.3"));

            Assert.True(IpV6Utils.Validate("0:0:0:0:0:FFFF:129.144.52.38"));
            Assert.True(IpV6Utils.Validate("::13.1.68.3"));

            Assert.True(IpV6Utils.Validate("2001:0DB8::CD30:0:0:0:0/60"));
            Assert.True(IpV6Utils.Validate("2001:0DB8:0:CD30::/60"));
            Assert.True(IpV6Utils.Validate("::"));
            Assert.True(IpV6Utils.Validate("2001:0DB8:0000:CD30:0000:0000:0000:0000/60"));
        }

        [Test]
        public void FailOnValidateImproperIpV6Address()
        {
            Assert.False(IpV6Utils.Validate("127.0.0.1"));
            Assert.False(IpV6Utils.Validate("192.168.0.5"));
            Assert.False(IpV6Utils.Validate("192.168.0.5/24"));

            Assert.False(IpV6Utils.Validate("2001:0DB8:0:CD3/60"));

            // TODO consider if following are correct or wrong ip6
            //    assertFalse(IpV6.validate("2001:0DB8::CD30/60"));
            //    assertFalse(IpV6.validate("2001:0DB8::CD3/60"));
        }

        [Test]
        public void AbbreviateIpV6()
        {
            Assert.That(IpV6Utils.Abbreviate("2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b"), Is.EqualTo("2001:db8:3c4d:15::1a2f:1a2b"));
        }
    }
}