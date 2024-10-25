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
using AdScore.Signature.Verification.V4;

namespace Adscore.Signature.Tests
{
    public class SignatureVerifierTest
    {
        private static readonly int EXPIRE_AFTER_30_YEARS = 60 * 60 * 24 * 365 * 30;

        [Test]
        public void TestVerifyDataTestFromAdscore()
        {

            var result =
                Signature4Verifier.Verify(
                    "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
                    "customer",
                    "ZHNma2ozOWRzamZrbHNkZjkza2xzZGFmOTBkZg==",
                    true,
                    EXPIRE_AFTER_30_YEARS,
                    "73.109.57.137");

            Assert.That(result.Score, Is.EqualTo(0));
            Assert.That(result.Verdict, Is.EqualTo("ok"));
            Assert.That(result.IpAddress, Is.EqualTo("73.109.57.137"));
            Assert.That(result.RequestTime, Is.EqualTo(1582516761));
            Assert.That(result.SignatureTime, Is.EqualTo(1582516768));
        }

        [Test]
        public void TestVerifyMultipleAddressesOnlyOneCorrectChosen()
        {

            var result =
                Signature4Verifier.Verify(
                    "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
                    "customer",
                    "ZHNma2ozOWRzamZrbHNkZjkza2xzZGFmOTBkZg==",
                    true,
                    EXPIRE_AFTER_30_YEARS,
                    "2405:3800:85a:9e80:47d2:1d4c:5604:37f0",
                    "192.168.0.1",
                    "73.109.57.137", // This is the correct ip address
                    "73.109.57.137", // Correct duplicated for test
                    "255.255.0.1",
                    "27.125.242.240");

            Assert.That(result.Score, Is.EqualTo(0));
            Assert.That(result.Verdict, Is.EqualTo("ok"));
            Assert.That(result.IpAddress, Is.EqualTo("73.109.57.137"));
            Assert.That(result.RequestTime, Is.EqualTo(1582516761));
            Assert.That(result.SignatureTime, Is.EqualTo(1582516768));
        }

        [Test]
        public void TestVerifyMultidataTestFromAdscore()
        {
            var result =
                Signature4Verifier.Verify(
                    "BAoAX8gMGwFfyAwbgAGBAcAAIKO644q6NXsbznBt9pHjLScL4egePvw71Ya1Stkc7sbrwQAgAJyvwpQNtvjZUiNraqLayqDDw4yKu4SONzy_4QH1yOXCACApdeG_d6ktUM7j-WOG23KbmhA4orHQhHP1F1yuMtJ6icQAECQFOAAIWp6AR9IdTFYEN_DFABBDeEx-VkruCiP13aZRmm6rwwAgEzT5WDKzJuv1Cl2se4BStbGsR2MmTZcuualnGvVMPYA",
                    "Mozilla/5.0 (Linux; Android 9; Redmi 7A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.99 Mobile Safari/537.36",
                    "customer",
                    "UxBc+ClW8Ib8J1q765jfxcjPGHQUtrBQbt/wFjFHFI0=",
                    true,
                    EXPIRE_AFTER_30_YEARS,
                    "27.125.242.240",
                    "2405:3800:85a:9e80:47d2:1d4c:5604:37f0");

            Assert.That(result.Score, Is.EqualTo(0));
            Assert.That(result.Verdict, Is.EqualTo("ok"));
            Assert.That(result.IpAddress, Is.EqualTo("27.125.242.240"));
            Assert.That(result.RequestTime, Is.EqualTo(1606945819));
            Assert.That(result.SignatureTime, Is.EqualTo(1606945819));

            result =
                Signature4Verifier.Verify(
                    "BAoAX8gMGwFfyAwbgAGBAcAAIKO644q6NXsbznBt9pHjLScL4egePvw71Ya1Stkc7sbrwQAgAJyvwpQNtvjZUiNraqLayqDDw4yKu4SONzy_4QH1yOXCACApdeG_d6ktUM7j-WOG23KbmhA4orHQhHP1F1yuMtJ6icQAECQFOAAIWp6AR9IdTFYEN_DFABBDeEx-VkruCiP13aZRmm6rwwAgEzT5WDKzJuv1Cl2se4BStbGsR2MmTZcuualnGvVMPYA",
                    "Mozilla/5.0 (Linux; Android 9; Redmi 7A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.99 Mobile Safari/537.36",
                    "customer",
                    "UxBc+ClW8Ib8J1q765jfxcjPGHQUtrBQbt/wFjFHFI0=",
                    true,
                    EXPIRE_AFTER_30_YEARS,
                    "2405:3800:85a:9e80:47d2:1d4c:5604:37f0",
                    "27.125.242.240");

            Assert.That(result.Score, Is.EqualTo(0));
            Assert.That(result.Verdict, Is.EqualTo("ok"));
            Assert.That(result.IpAddress, Is.EqualTo("2405:3800:85a:9e80:47d2:1d4c:5604:37f0"));
            Assert.That(result.RequestTime, Is.EqualTo(1606945819));
            Assert.That(result.SignatureTime, Is.EqualTo(1606945819));
        }

        [Test]
        public void TestV5()
        {
            var result =
                    Signature4Verifier.Verify(
                            "BQGCAAAAAAAA2uoAAvbUtF_k0Cy1Ha061GwaFFdcV0XibB3omHobRr5r89r8tXKft9QMyDWMWZSagCeju6a4uCbTdoJVFsibBuKjDJt3IVyJ_pyJYgDsL5j__zkEYksFksnOPDGFig_UntrPdOfkCiJE7GZlOtX4cNXOaAWd8IM5z3qbPqrZbG4raJ1ks_Xtkl1bjTGDqnYCdrVnrHtdROf8DrwOfj1V_LEIJP4ILyFeYOBxEsD-WOG23KbmhA4orHQhHP1F1yuMtJ6icQAECQFOAAIWp6AR9IdTFYEN_DFABBDeEx-VkruCiP13aZRmm6rwwAgEzT5WDKzJuv1Cl2se4BStbGsR2MmTZcuualnGvVMPYA",
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                            "customer",
                            "/TzoWbbouscbY+Ieez5zWT8juVkNahJ/Kh11cEBTb6I=",
                            true,
                            EXPIRE_AFTER_30_YEARS,
                            "176.103.168.53");

            Assert.That(result.Error, Is.EqualTo("invalid base64 payload"));
        }

        [Test]
        public void TestVerifyExpired()
        {
            var result =
                Signature4Verifier.Verify(
                    "BAoAXlvZZgFeW9lmgAGBAcAAIKxqaBnoQF9f1wBtD1vPQtAqBMx4Xy4zrA7MyN0iMC4AwQAgaO5p-QZrgtEnlY3PK74g5MlqnozeRHI5nYL6oTZp40_CACC7Yw3EIQW0wiVCSEWlggUvVhcrhw-xXFZOCib9tWxT-sQAECABCPgYJaYAlQva4rYGBkDFABCZxWZkzM2o40t0JXlSJ-2KwwAg6HUGWuqHH4y14WFXM4j-QRE7TChPURnYemSCSaJAomA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
                    "customer",
                    "QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=",
                    0,
                    "92.96.235.182",
                    "2001:8f8:1825:a600:950b:dae2:b606:640");

            Assert.That(true, Is.EqualTo(result.Expired));
        }

        [Test]
        public void TestVerifyWrongSignRole()
        {
            var result =
                    Signature4Verifier.Verify(
                            "BAoAXlvZZgFeW9lmgAGBAcAAIKxqaBnoQF9f1wBtD1vPQtAqBMx4Xy4zrA7MyN0iMC4AwQAgaO5p-QZrgtEnlY3PK74g5MlqnozeRHI5nYL6oTZp40_CACC7Yw3EIQW0wiVCSEWlggUvVhcrhw-xXFZOCib9tWxT-sQAECABCPgYJaYAlQva4rYGBkDFABCZxWZkzM2o40t0JXlSJ-2KwwAg6HUGWuqHH4y14WFXM4j-QRE7TChPURnYemSCSaJAomA",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
                            "wrongSignRole",
                            "QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=",
                            "92.96.235.182",
                            "2001:8f8:1825:a600:950b:dae2:b606:640");
            Assert.That(result.Error, Is.EqualTo("sign role signature mismatch"));

        }

        [Test]
        public void TestVerifyNotProperSignature()
        {
            var result =
                    Signature4Verifier.Verify(
                            "2KwwAg6HUGWuqHH4y14WFXM4j-QRE7TChPURnYemSCSaJAomA",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
                            "customer",
                            "QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=",
                            "92.96.235.182",
                            "2001:8f8:1825:a600:950b:dae2:b606:640");

            Assert.NotNull(result.Error);
        }

        [Test]
        public void TestAlreadyDecodedKey()
        {
            var result =
                Signature4Verifier.Verify(
                    "BAoAXlvZZgFeW9lmgAGBAcAAIKxqaBnoQF9f1wBtD1vPQtAqBMx4Xy4zrA7MyN0iMC4AwQAgaO5p-QZrgtEnlY3PK74g5MlqnozeRHI5nYL6oTZp40_CACC7Yw3EIQW0wiVCSEWlggUvVhcrhw-xXFZOCib9tWxT-sQAECABCPgYJaYAlQva4rYGBkDFABCZxWZkzM2o40t0JXlSJ-2KwwAg6HUGWuqHH4y14WFXM4j-QRE7TChPURnYemSCSaJAomA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
                    "customer",
                    "QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=",
                    EXPIRE_AFTER_30_YEARS,
                    "92.96.235.182",
                    "2001:8f8:1825:a600:950b:dae2:b606:640");

            Assert.That(result.Score, Is.EqualTo(0));
            Assert.That(result.Verdict, Is.EqualTo("ok"));
            Assert.That(result.IpAddress, Is.EqualTo("92.96.235.182"));
            Assert.That(result.RequestTime, Is.EqualTo(1583077734));
            Assert.That(result.SignatureTime, Is.EqualTo(1583077734));
        }

        [Test]
        public void TestAlreadyDecodedKeyWithFlagSetupToTrue()
        {
            string decodedKey =
            SignatureVerifierUtils.KeyDecode("QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=");

            var result = Signature4Verifier.Verify(
                            "BAoAXlvZZgFeW9lmgAGBAcAAIKxqaBnoQF9f1wBtD1vPQtAqBMx4Xy4zrA7MyN0iMC4AwQAgaO5p-QZrgtEnlY3PK74g5MlqnozeRHI5nYL6oTZp40_CACC7Yw3EIQW0wiVCSEWlggUvVhcrhw-xXFZOCib9tWxT-sQAECABCPgYJaYAlQva4rYGBkDFABCZxWZkzM2o40t0JXlSJ-2KwwAg6HUGWuqHH4y14WFXM4j-QRE7TChPURnYemSCSaJAomA",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
                            "customer",
                            decodedKey,
                            true,
                            "92.96.235.182",
                            "2001:8f8:1825:a600:950b:dae2:b606:640");

            Assert.NotNull(result.Error);
        }

        /** We've received these test cases from adscore */
        [Test]
        public void TestVerifyFewHundredsRequests()
        {
            var reader = new StreamReader(File.OpenRead("resources/test_set.txt"));

            int counter = 0;
            while (!reader.EndOfStream)
            {
                string signature = reader.ReadLine();
                string ipV4Address = reader.ReadLine();
                string ipV6Address = reader.ReadLine();
                string userAgent = reader.ReadLine();
                string verdict = reader.ReadLine();
                reader.ReadLine();

                var result =
                    Signature4Verifier.Verify(
                        signature,
                        userAgent,
                        "customer",
                        "QLzLkIOPE4rPRlnEdYwWdOMNYSuPuOttexVSf5oVBt4=",
                        true,
                        EXPIRE_AFTER_30_YEARS,
                        "255.255.0.1",
                        ipV4Address,
                        "27.125.242.240",
                        ipV6Address,
                        "192.168.0.2");


                Assert.That(result.Verdict, Is.EqualTo(verdict));
                Assert.That(result.IpAddress, Is.EqualTo(ipV4Address));

                Assert.NotNull(result.Score);
                Assert.NotNull(result.RequestTime);
                Assert.NotNull(result.SignatureTime);
                counter++;
            }

            Console.WriteLine("Tested cases:" + counter);
        }

        [Test]
        public void ShouldDecodeSignatureWithKeyInPemEncodedAsn1DerFormat()
        {
            var verify = Signature4Verifier.Verify(
                    "BAYAZm8qRwFmbypMgAGBAsAAIM3b90R7cdVO_XHQvxP4vA7UDX30H5Op9tBOHPmN0eNVwQBIMEYCIQCWNStuUP8E6wMLh8bgq9RZ3Xax1yMVnqgsizOVu8iWMAIhAPhZf7ttyM1E9lkcQ-KHsL_kXbABa9FHOFLZOiKM5yFX",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
                    "customer",
                    "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHl96xsx+bIG7sQC3KOR7e56MU/FKycI8NJyU5orUVEmaGxzkI3dJqt+cnMe16hciK08m0KjtzT25C3M/Mgwfw==-----END PUBLIC KEY-----",
                    "176.103.168.57");

            Assert.That(verify.Verdict, Is.EqualTo("ok"));
        }

        [Test]
        public void SignV4SigningRequestSignatureNotRequired()
        {
            var verify = Signature4Verifier.Verify(
                    "BAYAZpJ3MQFmkncxgAGBAsAAIM9KAL842opxnbcfKg_NiQf8KVO6Zu4pKsJE_AtC7BivwQBGMEQCICLjKiEx_Oq0w9v92YP_53-9xMzbM939O-nsWR6urYVTAiBYTte-BQMq8mk66yjcD48SVqA0a2ukcb6hlaW6Pk7Trg",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                    "customer",
                    "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMsDEzn7nkg+61sLIzRa2pd+wB8mw1B7IatRdSQKzssXxf6penv4nxY6Shg/Mq4AjzIf/Ghj4DYobQ6TKkR/GrA==-----END PUBLIC KEY-----",
                    "176.103.168.70");

            Assert.That(verify.Verdict, Is.EqualTo("ok"));
        }
    }
}