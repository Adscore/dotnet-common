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

namespace Adscore.Signature.Tests
{
    public class Signature4VerifierUtilsTest
    {
        [Test]
        public void EncodeSimple()
        {
            string encoded = SignatureVerifierUtils.Encode("k", "d");
            // Expected result is result of nodeJs hashData method for the same input data
            Assert.That(encoded, Is.EqualTo("çê!Ã¼¶:M£\u00ADxP1hÓkÜ ¾b#\u0082ê`¡\búÔä\u0096fy"));
        }

        [Test]
        public void AdscoreFirstExmpl()
        {
            string encoded =
            SignatureVerifierUtils.Encode(
                SignatureVerifierUtils.KeyDecode("ZHNma2ozOWRzamZrbHNkZjkza2xzZGFmOTBkZg=="),
                "0\n"
                    + "1582516761\n"
                    + "1582516768\n"
                    + "73.109.57.137\n"
                    + "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36");

            // Expected result is result of nodeJs hashData method for the same input data
            Assert.That(encoded, Is.EqualTo("\u0011pª\u0082M³<>¡X\u008DXÚ¹kµ_¶Õâ\u0018\u0006É¬Ò\u0087T\u0011s[E°"));
        }

        [Test]
        public void AdscoreSecondExmpl()
        {
            string encoded =
                SignatureVerifierUtils.Encode(
                    SignatureVerifierUtils.KeyDecode("QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4="),
                    "0\n"
                        + "1583077734\n"
                        + "1583077734\n"
                        + "92.96.235.182\n"
                        + "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36");

            // Expected result is result of nodeJs hashData method for the same input data
            Assert.That(encoded, Is.EqualTo("hîiù\u0006k\u0082Ñ'\u0095\u008DÏ+¾ äÉj\u009E\u008CÞDr9\u009D\u0082ú¡6iãO"));
        }

        /**
         * Klucz klienta: UxBc+ClW8Ib8J1q765jfxcjPGHQUtrBQbt/wFjFHFI0= IPv6:
         * 2405:3800:85a:9e80:47d2:1d4c:5604:37f0 IPv4: 27.125.242.240 UA: Mozilla/5.0 (Linux; Android 9;
         * Redmi 7A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.99 Mobile Safari/537.36
         * Signature:
         * BAoAX8gMGwFfyAwbgAGBAcAAIKO644q6NXsbznBt9pHjLScL4egePvw71Ya1Stkc7sbrwQAgAJyvwpQNtvjZUiNraqLayqDDw4yKu4SONzy_4QH1yOXCACApdeG_d6ktUM7j-WOG23KbmhA4orHQhHP1F1yuMtJ6icQAECQFOAAIWp6AR9IdTFYEN_DFABBDeEx-VkruCiP13aZRmm6rwwAgEzT5WDKzJuv1Cl2se4BStbGsR2MmTZcuualnGvVMPYA
         */
        [Test]
        public void Atob()
        {
            // Text Encoded: "Test base 64 text decoded with special chars: \_-+[];:&^%$#@!*()_end"
            string base64 =
                "VGVzdCBiYXNlIDY0IHRleHQgZGVjb2RlZCB3aXRoIHNwZWNpYWwgY2hhcnM6IFxfLStbXTs6Jl4lJCNAISooKV9lbmQ=";

            string decodedBase64 = SignatureVerifierUtils.Atob(base64);
            Assert.That(decodedBase64, Is.EqualTo("Test base 64 text decoded with special chars: \\_-+[];:&^%$#@!*()_end"));
        }

        [Test]
        public void PadStart()
        {
            Assert.That(SignatureVerifierUtils.PadStart("a", 2, 'b'), Is.EqualTo("ba"));
            Assert.That(SignatureVerifierUtils.PadStart("", 3, 'b'), Is.EqualTo("bbb"));
            Assert.That(SignatureVerifierUtils.PadStart("asdc", 4, 'b'), Is.EqualTo("asdc"));
        }
    }
}