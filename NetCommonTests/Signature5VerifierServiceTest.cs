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

using AdScore.Signature.ByteOperations;
using AdScore.Signature.Encryption;
using AdScore.Signature.Verification;
using AdScore.Signature.Verification.V5;

namespace Adscore.Signature.Tests
{
    internal class Signature5VerifierServiceTest
    {

        [Test]
        public void DecodeV5Signatures()
        {
            string signature =
                    "BQGCAAAAAAAA2uoAAhCUKWW3i1lyUuAnnx0sjGDbl-xGNsGS1sWWjceKtWwJ5rYaiiSU9n7UbjCh9MXxFaWXEZDNF3-_xpIR56KPNARGx2bigz9OF13YPSpSP6mB9b2RfWOfXYRa9CGGqGT2fleE4O6GE2qzPVRJ8U8y-O9ZkixcqseFH8Qpy-RS1V4gIn9UYIC6nc0OgRzFonTLHymJJwmSdBLiDzp1bJz_vGZ2JTjv00jZ9e1-aNYXC6dJVEuzGkVLdG7f1QFXhKWHQuDrIlexm84Iza4krHgcefTmcZ_zLtG5p9Vdu1f71nXYV6FF-LbRTO_ijLapCVlYWxWSzVWep4KhFZLFMgdyvOrI8wMaojYuqMUHas1AOJIVhxAbesPVQ65b0t9wiZJ4cfO0PVITO__SVgEiwjd1SMJonjg5CkcPrj-o3i54YArZXTPyPvqSuOyLvoeXj9ZajWtTOiMnljf5h-OT1H-cuy3Db50tOtKtRLy6u_sJgN57FU2xWQL7I02efuv19_kUvw";
            byte[] decodedSignature = SignatureVerifierUtils.Base64Decode(signature);

            var unpack = PhpUnpack.Unpack("Cversion/nlength/Jzone_id", ByteReader.Wrap(decodedSignature));
            object zoneId = unpack["zone_id"];
            object length = unpack["length"];
            object version = unpack["version"];

            Assert.That(zoneId, Is.EqualTo(56042L));
            Assert.That(length, Is.EqualTo((short)386));
            Assert.That(version, Is.EqualTo(5));
        }

        [Test]
        public void ShouldDecode_v_5_0200H_OpenSSL_CBC_HTTP_query_payload()
        {
            string key = "ThKCl73KeIuOOhn2iF7tj+bB+ea+aBkLcfDLU5X963w=";
            string signature =
                    "BQOiAAAAAAAB8LYAAnK2SqmIFSeHe0k3p8yAVqT3WNH2kYCWNeTeX6Xb3W94KppxV6h3KeWYMUsen7IS6OCCTw8UtivFrothKhJFzf1VgtO-3hAQparXW0Qp21mJ43xQIP2t-s7JMlX3fiw2Aqve-xsdUPiVSHnMKpZREstkC3RQOBiAQC1YWomxY9ymIl6eGAb1PdzxPXqoGgEs0xBE9zNLhqU6NrRBuCa7mQpCooivUPrmtzVJWnJsy1BWn57GQHxHZ3IE4L6P0iDXK17kkaLTLTfSsbHXmgH5D2H7ESFpoPbobgJ6IXWNofN4evDFYeRoptWTAivogv_LDzGSAWu2h6NvmBGIr_4y5RvVl_8K-SaNKK-P9B8oqyNgL-miS70vgnE5k3_De7W6hWJW-qaD2WMzxi6isjd4oHFbcGzHAUBam2CCkolJRr1YwwYYi0JTK8bYdLOK7saOOsoMq3gqL5SMrm7li7BCdI5T0TI02pvvfKnnWi7AiokqRwP1T6X0-mGC9mccoQ8Q0uOGo6Ew9MEDwFN8HBVdZ6nBSAp1JuGp5GCl1YeukWittuTkPEs9rF1-ZHCi9is5WEYQMwKZHX9n134F84hTPo5QocUVSIKhh02DrXMAe8DnZ7lFgkW127p9_KgfcVxZrwLxWFNnB6wf3_Q4V4QCQR_6IrxdqN52SIibc9BgpzUmbkr9vdWEY9TgZEU6rMNShMDE3r1DBTJdupjzdM2rYcrezglyBM6hdcgsoB4HLcSuIRqj80U3ve_094mpSUxbYm7BGs0QkNK_kE4av7ZE369uI5yBgtivxmf6cZowvRDavGrpiHrKUs8B0E4SflGI82JyopqD65isCbiY_gxiUFlnpewoTnREbejHGLe7U9BMbnFWNB97Nl7Z46xRnn6o0c1yushWJ20zKrCmMwkUCBUjHRxn9GaBRyFSH82Wp8uh1oAwtQS1wC5ybUd6CxcNBx8RQsAItNzRaK2w_iVZkSDGGHlvKK5hJ4pct87Ga5rB1VUOfq5rNHjNxk7BIxBdQw_6mnFFfsPvA4kCYq_QCYlsowo-g_SErNyvYJ2qY2hpvrgPiSjF5AAyHB44ueCoaw_77mokuxUwSRerG4aEjalOm6jlYLc6PkwUYp0Ff18noOnEYzE6D37j2X0wP-oiZDk2JOyPeAfSwESGpXpByqdLtB_ZfoVYiL0zmxCJxwP39V77eSMhI5dI4S8mng0VsOcDFuzqdUtaZYMfbeozk14";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127158L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }


        [Test]
        public void ShouldDecode_v_5_0200S_OpenSSL_CBC_PHP_serialize()
        {
            string key = "Zh2FMfJ1p2ma0VMHqhOnFZKgYhcovCb+IkVSL+7mp18=";
            string signature =
                    "BQRyAAAAAAAB8L8AAhAO3wIpo5hDZL-JmqUBjv0bXxTBGYhMnvIM2CVQDKYgRsP_SRsw1WF5XmZpf5BSA6-ZfvcfxGS-F9u3T2P9qX5B1Vqz20eTbgwmlqUFKm9s-YqXLIf8N5CoBatA4d0XucaJ2ubGgnXQgUvB0EIzZhwBH7dNP9GiMhK794dC-TxKpcvgpuXL_XhufUeMfScZBrKFBSCEbNbJaCg3OiKkZXqK3DxY3SmKNhHtoDuqQ5N9fnJhVsA3WPOSjar8SXKWx-tl0BSyZ-ZLXJZpbc6n5Uw5M5cBtZEVxPAb1b6mwMCicicNZwA3O6Mz-S6s-BQUrTHv3GodMVdYinoKtPpVb16aOitcOHFdnzCZw7fx2v6laASLsFiyLAJjSrn5esXMHU6IaoCBPM6M-3GyGAuU7as5edDaMX-m2r-7PlTMucX3_CGyKi5vBbzvP04dVh_rTZ0rUzPOPMY-_DI9eYWvx6HItiPC70zuKDKxI013lB1DH4Jopq45VG2h6JQS2MghdNUULiYqXoLxeK6L0qnPabOL547Flwz0hRbaFeRQqWT4zDZWueV5S1XcECgCeooaRNL3SB08Mx18EtLtoiuI_PC0XrpwB-kVwi7cngxTlpj337v6bFF9UwpWMiTSnpJm9oYGlMunhugLjSGP6eHofjdC6yrGFFQGn2C1Rkgcf61qu3P4mv8XJx3SVminC_iFsowU6mfpK2GWnXy4tI0ioBmojmwH53Pg0UZy4FOL8F6zzyGMdVbVQ6IUNYdCtykCyuTQBV2Ntix4SSZATVrPv_r4M2Mpc_IwfKDzjIdSdvYArksy2EgOFrVqmbZoWDYxE1OlwJnSsThvZDyzvA77V4NlhcSC7QXNRgBofdTevdyj5GmKFtnX-845REwWmRU7R2ajQk6nwkxgOj9P29VfFrTdvGJWR2bp0wYXJOhmWmJFmyAP6nCUo8d5hYQCAIeFQbNQePlWNjhEuqcYvx5bJOTw9PYaUp9RqHe4z0funL4dqvXfmdlri-MhA4DOv-xIQHtokZHlgLEACtyqwVz6qC-g1Zc-10FXbleN3u5GlBVPp0NxZ9gEy0T8Q_4fOtGaZvgcyX6Mf2m2Dm68B0ZbU6TDKCV6yQ87qABwnHhrCAE94c5VK2USuBWgtVXYgsoWQN5gHfSnU9TqXulJAhXYbbOlm6lX1aX7ckcA8yCxbSWxidRKIN6al2-BGQEAsfRt8aewvatJirLYObxdH54MLGGvJ18oKxp3D0sHldlVm5w3vL4bop2QTnywwj6TBjHkkNYRK3QYu56Yej4hgRXSAOmWAuFVSMEi-OqEYXiCz7yhLnFdjbzqMt19R9mhp_wAbLSme2l26hIDdN9etFjJ8x1xcqhhml6UXw6gilnrfMybQ0TtW2saBWg-R4_Ui2xw38C6WvcMH945dah1mRqKK3rheMWOAsM6sfrbxdPAt8yCSDGPvFrMIFiM2xQuX11JKUY_ulS6BvVbmQZwlMeo_OgP6tKSVCxZ68PiMlZyNZ2g";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127167L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0200S_OpenSSL_GCM_HTTP_query_payload()
        {
            string key = "CxT4sDcIUJerY1KMGIIra9WOLHO53aH1vnSGaSW4+wQ=";
            string signature =
                    "BQOvAAAAAAAB8OMBAjKyPoGJDK2Z0_edXjvw0u386eWfXX-8rnDbb3BuhWU5ZSzrelHjHcY9M9uQ-m3lGVEIyANuWNEtwMNlcpkPgWJgJ-B4_bQ-nt__hUTKpMsMfklhkHSPRC-V-kDYoKJMiJHq9LifBTtlDjvX2vLZJvoA_jpp8yAQJq8PVY-l59pu2hwXhSIkP_5ShzQVF0SC3obkcs3V9SwrBg6KgZADOfat5yT3y4hd9essZMWjPdru8lWyiv9tfzKJBntkaF-4TLlkbGeyObpFQQOJkeYvdqKRpsJn-JKLshyU3T7IcxofWe4iWqb5HErhPhlEgI_HlgciSktYIJkGOe2-TNj4xO88J8zcxLlTiKd3uMaKBS3OYq9xJ-VhbzV5oLd-NwOzeaVMgl6z3EPhZ-inbPn_1wsiIfQRsxnpe9eYA_YsLE4wENGVBYNDKNsikhOxPmmpdWYVXE5-ffnLWkucqqwWQe_LRIF5UNVCXLhO0XyF53Px42-RX6GSYDyvQduU4qguTDU7QH6-Da2ey1bkltKJNCpYRu5hqtwXBTAZLSXCjYFjqogxu9KMefosVWAjDQe3_7fnPeEtaIc4qHKy3fGBMs3ElgGYrt27gdEuMSOaI-cN21_s_c8TK2eSgqhBdTSNphuul9SDl_mSjlyvAWu0DRvdR4KXzGwWm9995kzc8tygxJv6gyuns1X-RWAgNB489RFMmpxqgiSdQ-1hJFE6DRx2xjCaswsj91NB29T3yRoDd10l0ucYVcYzoG5SmoulWdwdgdRUPojv7iE85LRX7WJuMtx90Edm90ezKQMy8lP9OMKykJAnHNxbV7fsiToZ5FYjtVWHmZxtP9HJLYHLABrxhaZ-K1H8TKjVnKcM9fkuXcM06yJjGdsy-yT95ATqKh6M9XUYHxL3IEYF0dorxmjhW4mAh09S60lBhPP93zoVR3dP6DzfduutLqG_cbym_eaJ_7oqUDkaOeGze0PQZmcWC07WLANSafHdckAOoLPjEsPya5z2DZHQvgtuJW7mIxptBqSYmM1AAeCvxWaGf40Iiz40IhQzbnkIO8up55aVHxDe2H4NjS6zqJ3ZU_cq7_rFD1IhjlBoMGMkCV6IODUMDerHXm-93KZcvpNlAwfzVC5wuLpQv5-2cMzAGOB2UbJC8FyOtahyswyHP8LFw8tUBtIxerctXR-cpJzTRtNrS63pi-7y31DQsqS_vDSZxsPdBvZEP_J6Ecy2BrxpEsVxRHkr_zLUHwGYyEeC";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127203L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0201S_OpenSSL_GCM_PHP_serialize_payload()
        {
            string key = "6CFIGSIKNSq/i0iIU6PfEYELMoejlHnr0iLC9k8k+X0=";
            string signature =
                    "BQR0AAAAAAAB8OwBAhvQ07QigBM-LS10gDMlM0QQGjrdXXicCWj8vuG1CLTHNSskrBeJlwnrcEmHpmJJQZOgbc0YX_uiaNngRXzMZiEKQuT58wscKtNWbDPHozALfKRq5zA7ATpcTV6OKwlytceJo-H5iKvs5EBs4YhPw2BEOnGhWB_RpE_wwPj9YQcn5DqNNoeCInBoNbgnVnx26SPUHZ4GzEgd9Wrx2pn05mnZlCvO4hZK6QXWjJ5PMrIAlVQ3i3MzpjON1Yw0xwHKGeAtsbIQYOqZ5lZbApy8Rp7L3YflxU4SxU6nuekV7wl7zUGRtwhns58A82sN2gjB0RyZkqlyBYr7t9UqI_4HlzaVJ9p7iwxBQ-XeoUblEd8ZqaswD_n6t56ZfMdDcTqY2V-X9QpQ9weKG_yUdsqHpyQdE5DHi0zj66ZmceC24HzojkapZjPTJt7UGpo78X6P2WulL90oCLDcau6EJSEDoPRUjCdv2i9uyjQI35sE0E5LfOu1tW_kFQ-jkb4SJQB-Ra_T9lJjwXrmBTTYmlV5AslV6qbCkkQ6ArryvKZBxyT6Pi7Bl1mCbNV55G7zrjDeADGSVP22JBell-navFbrPJJ0_MIKaN8q-9ih6glpyBV8bnoue-Q5ZPLBkj0ON8xOBqUukSyhRETN3dNAsHZNcmQerN_D5D0qLAns7NTYZfBkVWODMMIrzoxMlGvGx7Y7lEG_whhPkPXM67PjfPGsKgzxHrrMstTeEQnDj1dacRUmDgLCA1M7k1uXM7ekTXl1RqtE9tyuuwMAQRcanjC0cFdLtNt0Ynaj5mFvtRapYj7cjn0zL-VTk_b_XB5As41lhQGw1O1ogWo6swkrA9FopQtaF11nD6G92iplsv6eGBNt3q7dDuOY3rm8K5SBCgf6e4iPEXq9h4W2a07S45WIJqR_UY4sWJtTmSv5YYmfZZ08KnBPlPJeZ3RpLVArajVzNl3u9tCMVFmIyxMYRY2oL8bOGkHYvfnxyP8lB9tTf7-IZwDMciIo_YeeUSoOAedXCP8BBAUI_fP9wVY9DWKou6Zk7LJsmnQkUPJTLCzh2IRvmJp9KLSVPGXDxwcVaXe0_9wHgPX7NK-XNkuBFZi42f0TyiQ3N1dgzqwl6eBpAhr4Cn3d7-otfo1DMnCg_V7KqZVIyp-4Ez5l_Wtlvn_bgmeaZ2LevPuXT4DLHgKGxA4XGpmWVH89G2DlzHS4hlE7pW505a4gtkZSntBVqHNdkE76nu-DOqCxTn8H7ogEZftzFpz-J6T_asqK0gSUWLrDjBVNwujZF6XvLkyVJO2ShxC9axuwJoMDsGdJw51pP6f7h-dIVtkaQro3VrqSvzSLlmPYpDILWiMARlzxrblipu0kOOThIXTsgkEaOiSSPWGrgSdCnl0JAgyfuBJHVCujgKJgzi1veX_bnyvImwyzG25AYtgwcuTYqdZQ3k97-kqmL7dFm_cVlDkXBu2QZFvEAN9fIl4pOyyYNEUVT5AolrO5WOxBJB6lbdPqnKgXRBUWYIs";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127212L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0101H_Sodium_Secretbox_HTTP_query_payload()
        {
            string key = "dj0lTcsmjDnDYPSL2+DQPN7QwirCQOlqnPhiXwusEM0=";
            string signature =
                    "BQO7AAAAAAAB8RABAQX93o4s4rKP_WfrdzFP6ATAWgpXwS8Y7oECAcpVJXb-rGN2aH0KbFw5zvhEpoyEml6vRM7ePFigDUhDProdHA8uw1L62k57fX8t_j0UCEI6_oKHTvfU_fbfg2CXf0v64oRHxaKkcD3BqjQoL3ow89dAWX4xOsWHyO77xvxeh78yE7GTKVm8NDNQNkWbaLvv__y8vW2PHamWkqJypw9q4KYZ00YuIkn5DW5SmW-m1InOOyKySX64QKawwfsNqDE-vZBzFhQXLNGRpOsu_NWadjKE97Lm_1BLJ0QXscJmI0N77TyrpEjclI6b4yLiG0W_dkOSrStk3WPzbUv_dbY2UDAOoZaFr5PsXGPSEprVk1FNRmSaxxnGqYm8hD9y3c-VBqnDGPZIGpP-JXLrJv1q-s-XJkXXDIJyz89rDnRf10gn0iEC-wsocx5QBQunD1PNnkB8_r5xVXxKG2kgxeApVH7Bdbs9zf35enjD8VP8tA8-kiDR96jhcY0eJzSqXrMsRfpVqyPsJeGcex2DXNALWo8f07ikfH4fZxiQ9dzUTsY9zG0fH7SiRl1QexsKM6ICeKVSbublStF-XnbqHAc7BeShJGBT1z5qF71i-vlut4xY7xNrgpiWX57ER8d3IPqJEqrktyAslNz-LKKLF2N5z03DZzpcqmv6E6e5PeI-eURYK871Xoc1vO03BUPjcyDH3Wge2qDg1u_38tP3p2V8deLYofk1hsfEyk6lLoCNd-293jOFqZ3quifwujueEmQ4NZwht9dtk5Ee-osYezvKT9UZyTjVQrGO6WWklhLTfi8a-ApL8M3_7fFX0MNL0JqQTrKtFJnrWpdH2eXOtAPBbmIfPGNXbei9R_kOY_v3FmHLVomRCCAbftVlwr8cxpdVn3CPu5lls9yR15_XpCFm8g4QZFQPM4sM4UCPlXQNiGo4M0DAFMIPFBsPYam-TAPTqKmPpCWDR9M-dHFMF5MdBkOmtAibElnRXuZxqBJO2nl8QO3zGI9TFqS7v_0d2r1ADCAjd9hWYJXcTkl1dWbo4Q-IFxKhof1d3TjjVf3wTyVzsiwbEJUV7FXg31qAyAZzSn6EqWhGAd6ocdQvsXS6KH6Q5FsTM6S5IJ4o4q9x7YN58css97WbFw5RffPNHNggU97sEqG4ZcPEwMo8yXNK6V03DJFgLBC2F7C16vzZNualajF92_wsJ5XgjzU7say5ucmDRtQA5IEisPz8jl9vuLL8quS-I-zsJA-MJh6QsowPoegk8Ur76kn0";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127248L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }


        [Test]
        public void ShouldDecode_v_5_0101S_Sodium_Secretbox_HTTP_serialize_payload()
        {
            string key = "/UQKL8veLl4KzGGXGXN2U/iOdXY1wMd1QIhgsHywij0=";
            string signature =
                    "BQSAAAAAAAAB8RkBAVravE3TQel2zPu1jfRm4aegYBg2Fpld-_wEbDLrpKMQyGu9G_zwyc2xClDDzMrkA0PC7MAM_9XzMbOjetW0LU81BkBPXF7AyBDqVfmkrLwI-cOacXg-L7xAlgnndKwEXjsm_NZmwE1c0vz1VYjNE-GwrJYQS72Al6tmha_uPEA5Bzf2E1RIx6zvXNw7NeEbNsFyVghy0qubMSvUInxOCg3v2eZqHaajQF2SW3kN9SDw3tZmJ2qIqHR-rGDoszPHxG9YRgD2ZhkipVA8sYpgyL4r88Jbs8Lk0oSYBOqh5ZZJ0ihn74JlpRcAo9_vX1gwkeyHq7fm0QVGCgBEKdRVKgiu8csGN4qeSkGNaRj1Ct71fkmdiUaxH5L40cIB47ljN2dMS0UI20zvDiQ8zqQ3o323-HMCAgxsmLt_Vd0C2XFJxpVnrEexhvjYjp7vwaS9bHTqNoY0ZL2hEZB3vB_rER43OFCAvfJ0LnkbBc_ClfRv9IkO2zr6mvVPZJAjW_dQvgdjHmxixzUQrMkWQm6KProR4Nql9HuG3Pq4jTR2Q3iNcmTvPEy4xij-ZAd7J92G2vxZawRxVQ1Gkv9kmuvQUVFugoZ2mrg9BGIYSfpNzPyw5P6mpiXjRtrMwyo7ypVJLLxJ_DFy8_yU1w7iZWS1kjlY-L9ZnnTdw_Ohj_Y1b5whUBYh9ercgx6Lav2PI0ZuwPb0J9aH0OeFHVt35cNSgJoUn7yx_MW4UVBNUraoS5KuBx1NyXt7SiNvr60KizvsV3N-jaqeTJvTs3uktR6z2zZtvPCEAJpBQTQjjuEgApMz9dX8mCFERniXtWIqsi8OA6wphLBk54S3n81NOwU74w6bDXmKVREdpemMu37ccv3tuFw2ziAfkL_e08858Wdh1XHHQ3xmOr2C3AXLDjZ4tFeWHS1S_tIf0-zO1leYSJLGLDPtPsTkwrn7kXVrSTR68uMqTACJRflhpIPIziasRCMEJB6s9XGRtsl_URwBvHAtj2DG2lAyDavIZq4tWPPLIRKcMYDxI3QR8v5WdXDDliWmReatQPTN47s6LfbHVr1VvoHS74GxkvG00pqGuzfrda7JLef5gOxkOeV70p4--LIx3QAwB5XqtxurxpJEq_okfeguL9ddpK0ssLl344nXsy6njNytNjGGZ8Vo5TOhX1WwYk1JQXTMocfLlVWa1_TU_Itf0HWN1Kfow1npgEJFEKqOd1V6sCFogysbuqn4rTF6InCqnT-O04D2hHpnnBnE5oPwIEt1aTgubgvyunBeMQjOVKg8m1W-toDgwJtsH6GT6a20r2fIEnW-aFAVBBhNcjZ58bZgxtEvwHbvbF1TiDWyp4pXBi7TYobQfMWgpKHLrmo6E61FiLyEu6v853-K_GT2Lk7NMEoab_Wi1YpxhG44vty9uH_w7mplaSZaT47C9zOQ0DBi5X_Hw0fimWpCZhlzHpgavuKMeypAY4jIgqM1h9r7f6cS81gEvMRrSs0wf3cx1r3tEhu1YYBaIo5VhlCy8W9gRiHMy67KbrM";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.60"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127257L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0200J_OpenSSL_CBC_JSON_payload()
        {
            string key = "3UgDQHdHL3sX/Uw0F08j6rWUhpweCJNk4X+4pSL7CbY=";
            string signature =
                    "BQOiAAAAAAAB8NoAAvytsaUp2lqNqXg1Avj3DBcRJnB-h6RxsAHFH2gAyysk2Bol004xvla3rfyplZkrIznOQwp51sHII5sdQ2PlgkyE3GkEmDmdFSHH2i60zd3wqkR6g9QJVBWOWSJ7kZszWRyGIXozoKZCsEaB2Ep1pHayQ4JU3RQHQC1tbGs4IjFcagFXPlT_oFsx_wcC-RvkMfBZN0iBTfVwyjUTPPk2-4pYdx2R-P_6iDTFS_Ferrl7NS5PclY1TD5wd7vhQE1Kot0B0pIeECxSYTHvajKX-A19BPOYS84ZKMs-6DOKtoK3nDEB0xSaOlomzyyr8OW--Dv39Nn6OcnovKQtpbGa_OcPWYP8QpVJyzebyYWmw45bbP_EZ57F6MRsYbv05rJRKmZAOGOLThoK_dQ1fEdmW3GOrX3Y_55uJvlg_u_dLCfsQ5pVCS7Gg_3nTOgOh8beoB1nLrxBQnpOQRyvS7y0FPZ2xaDQ83dakj4k9wm4UMEAWPoNAjQwU9eNAxt1S2h48tnvnty94PXoOm1AIB3sLrmLeHmSlipMu-LtWkNhbXHjeQjgXiWTywAhXsXrYoLlWIZceaaHqmXzdqomjTixblJ0CvvEwvARatXdfay2NNGFK7ezrC28IHaloI1eJaOO37ALDzbWz1BhxF9IDXF5EjYHlM3FpmqX7I4ZWKgWRBp7Dxagcds8yo81McdATEEd8x5TCI-0Ibud0mtAST0xG9UNriPxfZsGapDOU9e1telD_pPurulLGCm1wWq-JPInK90LxPtmuRFQHpvxs0x55L_LgepDk2PHko4goHDBHakWvLN_EnlLk3awNvALXNXCiKDJ8EMRmnboQxFDN1vqg0dqB4g7RSF1K5jeOdFF9bPvogbKohTWOVZ0SAl4EI0T137MIAhpGH53mHk2__FlTvcHpQZX6WlEDumHGnM6ew4m9HjPWEUbekY4WI9PfWVf2lANO8HXeF2PngbnZlc9Zd06x8Ii1G-xUSF6ReKyIUEhtYiFD37iOfi_DgcAGxBxvPryP09v0OTzsTftJaGA-m8cNsUxUbMJaqxBZa-XboGuXBb_3uAcecunZCiieoYo35o05_TGgXabdMK0pet88ctWgWCJYVehrXZhHgoHnQgH8AKRo4AFhMPRMApEGuLtDkx5Ui9skBXfpNXZzHciroYvtZumn9y80-BECWVVkCpEM7mlh4v1qoZsEuVZl3Bwy4s5Rlt-HeLoPJmXRF0anW0";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127194L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0201J_OpenSSL_GCM_JSON_payload()
        {
            string key = "pfxKlCeCldpjHEv/vjJZQVhqxoMAm1iR/QrN8pvgtK0=";
            string signature =
                    "BQOqAAAAAAAB8QcBAuzw_Obd7r_-u8MWj7EZj_GeM_XGSE9Dv9a3g44dBpYLCo0MFdcejWgcXeKmkD89umMp4n0oBYT7H1tucuvH9oGaLyP4bkVexoiV0Z19oIa0S9vKHi2E0ZTyjdE6MBWtxsIpgb4g6yBVBk4fBMRxmwhOY_gWf7eiEamS-YUtpvPmFkXn54qNgMc0US21l8fhIAnwwh1YbPkvk4SGCmBuekxKTPcU6y9-pAJO3QC_eE9kcd65XXZvboDN6nBcIGhA8txFZlNNbX37Y8ORRokU75K_RAzZ6n-8WBKPc4suZoS4LMp2d8vszDMDrKN-8XGJ9bdqOUQcw3j75Z6J1N2YJlQP9lrbEWctxpVyD62RQXKi6BqkKofn85SD1vY71LPKqxVg1Q-A9Tq_3xvp72f3QczwIZIw9_EesCWGdLzcywoa1qJKJKVqVC8WEDw2HF6lFArLgSbSmNci7lMkRkuj155GNIM5zzkE-g95UeceHx_UsEWWa3_mWeneAPyMB7NrHCyRQoHNogJFd6lMYvb_OKQljWvdeTRMFJOZhLd8DdH8EEIlVhVF3yEM84R9WyyWEKfwktBu9DRZRbupvWP8y9x4BcEFpJJFG6kpaNomJ-5TBKkKvC0-97Yw45SHaL_wLDK8OhDSBSw-pNqtggSKuXYnBTt7etpkty8dRh7DV34LBBjOn-dOqKWQB99hJlLVWbz_TXovjm8mohospcPxNuJ1pGcVYMo6cax3MhRU7jBkeaZrDeMYs2oF3gSg9I51riDT41qOp-hYLzkFyaS8L7UhYBuFugAH7I7wwHlNqO9JBJXcm8JOlJIZSrXAJ0Vqq2wcRAkpPrSPQYDCXChMsaS8J0lJl9xsydVLWV1arBNuyC_aWKvk04ePum2k6SJUocveADYv46VDnaAL0Jp_H18kBtv1_UKw7qtfng6CazS9SQMhlLMRg_pOS9GN3DbYzYp6OFBRs0dIbcgfx5-akdN9D9V4mN1L5TCEmFqUVpCLdT7eHLa-YyBSLzLwGWxCN4GrP9FtIFzN0CiLq95oHNjM9i586XD6TrkzZ1tctL9sYdkEjieh0AOM2uft01xWXrV2J5M4CCnEj4xsAiQpy1gq1N6hfIyAW7TuPLn5dibjm8ynVRgJcEvVvUrmKAP2ry3rcTT2nDlmvh440INDFBtS4lFJbCm06j2sKWB6XVtItSiJ-L6kiE3SbbVb0l-bW_S56cPdNFPUFBNpzuTi8L9f-bZoTNC3TA";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127239L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0101J_sodium_secretbox_JSON_payload()
        {
            string key = "bOF7DZ5yhmmLAmqiAECGRPzQn1jckYImJVSBTV/Ib98=";
            string signature =
                    "BQO2AAAAAAAB8T0BAfu8QkQej_XSVkrxJRWQCCfrBo2uI-JR0s2e0oOz8bUNWW77iqRxVwYlpwbj4RWs-UYSXWV-Hf08iwaZGHf3Hy67BD4BwqusR6M9mPjIiKcCvkHNSboyn8PZ9YwMggyxsTj9U6_8_D-qtzeSMAFwNkOveBJ_nIuIc0fZlhie_B6_lgi1hR0afQi-z5WeTeYd_RoALtvr-1Mt2lfeOTXvYzQL_GiAVtY85Bnor6HgFFG3rPSKUPnlX2dd5ZJKIAR0A42-rOdiSWkmfjVVNL3jJuBnv_afFAJ6dHDBwASg93XGaBtLrU6fzwnGlsb3P3gsbH711xfz-mKU61QYYBn5JzquPPJLtm0JjhlgYVzhRna9A8qGsxn3KCFZADRjZywZXC6pTo_e0DdDWvIPnGHluMhOA70NKbX4SyehD9dFqmLeE2d2o9IJGsgXC7pA8d3NO7tripPwMbe1wG1POI8fITxGZiDbRl4-967ZV6o-K36VBvrO2aO3TWkqskzRD-cphM-6n1R6adVnrOesOmByCfUm35VIQGZNVWwPdISMO9BqwPyI4JaFd_t0rtXqR_y-tDEF2Mao8yVZDjkI-EuWxYl2K7Q34BFSo6nOJUfQiv5greM9JneHz4i8PEb8xKyJcWySs0TAySB9ejs0eWf8C4xMK8Rh_7c36xpHkcqex1lF5KB9cYXTgLmJkFsj7e4soQUu1vVL1EgmWVKWFjfVvh1RXzEfUxwZfeTWsU1OCgGQivE238oUxDzzrhcALSzHjsrQtwt-JD1Q6dEQl05imfwXrZDre95SgBRV5PsAEowSrudeu-cYz72XvmS6uH5_ywamyifQ0GrYHnrqe6JyGovrAsSMQ49-1JmFyxBTecMq2sQ-cqIRR6_4q6mh1MhfTIQOUrkU5j08I0AxRfOzS0bSzTqMy3jNbIVlu6cJTy6EyVWrpl8EUOm2wIhTfjSCzFTMdfx2By9yHCxAYcDrggnjiWsU6brlomGxVupSebeembKT8yGcy6KQWYRRgdGf3lvR02y9CDLeYPidjWR9Ilv72EbmQtHqqXhOmDjT01SO5GC5KTW4sfz_RQeauZbCda4qeXMrbUcHcZ4uLVd8l6to5FYJRoAcQ6qpI-NHb4SmnGEs47LOy-TWxxE-atcSfIGDp4BvJLjCShC58VceO-knz7abv2z55a5QXYQhIskKPpRnvIPyR_30M_8JJ8c4B78bgWSVckfO7Mr-ilH7CErgJgoVkhEF17b6fe3-J6qsx6S7WQ";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127293L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0101M_sodium_secretbox_msgpack_payload()
        {
            string key = "BeS5oTG+hCLquBAWDTMDZwieDb9+plBDNjBiY1g2nqA=";
            string signature =
                    "BQMsAAAAAAAB8SsBAe_xWI6vmIqNw_k4Ricw0pKkzJPqazJt-Jgs3jyw-LkPYDt2QTRUmjZYapfKWaD9e-ZNQmcBFeoUi0ZDJOytIlHnIeiiq-6dNJL5PneMYaQsOuhouAxSIYVrk4Yqe-DYtBWxI7MDblWGvo9A-36pMEU8Mq40zlWOPuDFDDuE2QeQsaN2pzke0rcc6lqV748dE5lB49h8rn-mwqk_KG9mHHYEysGURTZId8iPyOMuPVzxJa6vLilO2rhxBDKS5Mz9l3k9KIn2fZL0qwOUco6l_JNpRxkMa59oeymug7QCcSFa5X8BZQXC1R96YmicTDLeyC71AX-pA4ti6HYSMhaK-5vIUqIfzhoX0Tpa4R0bKPLTT5gq7U68bSVTolV1XMbXU75EsSekNQEp2B3K0YyQ8TsC17DEPDNdtZ_eynFXWJYZgreJskUzq1f-7F3Sl_8xDBFw8fA6PnitfPKbzzouWJ3aX3KAFOHrno8iXiYsSVtVvM5WyJhQCTEkUfUFIJfEIQ92lz7ZDN6Yf5TZziqk7mN2os0Y_1UcEtimMjIJgrqLKTgKNaFg93m2NIxXubxdkMwSVsWOXhDyiL9q4winprvLoRQR5HMiiMrwVMOFej8CHDtFt_2-L3Rg0XdmMOwVU-WzmshNNqiFm5UI6Jn8VSIgzc2DFooTQb0ixlWsbgjr8MKPXqwmNyuv7PYOnR5w8A0NZwPzVuAJvOKlFQ3M-Ais-pJgx2l0GztNA_OQZBvcAAxFgf-9jJdRm23NFnQxLxoEvTghvQql4wqnGs14cTgpGzwdiQRAQY-T2twPpX2PapnwX-r_Yw2FDHhQEv4DTPQLInScTF2tdzNbIBMHM5fsLSuWOeF26C1VGDM8EmeUXoyYY_rMn6OZvrQiC4jXT2XumDvdoNnp39XnoUHPlVG-O0nlg7icE5v2YtB0CaHR49AEClgDdw6Z8pM_s92mUycWVQS3Q5fCfiM22rbpvSA1eOOgzlwikhs4GRizusfliweBnwHwnzOz7hnoMte_fpuFmlcaSz4tpF60-Pbb5Bu7_-V1o9kl1K3EwBZHro2YWK-UpZcbJuOs4Q";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127275L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }


        [Test]
        public void ShouldDecode_v_5_0200M_OpenSSL_CBC_msgpack_payload()
        {
            string key = "baef7lRRj3U4Tsqd+TzUso1LfnDMh3TumcHm3wLe8xI=";
            string signature =
                    "BQMiAAAAAAAB8NEAAnX5VyeHU8GPME0kvcEP4XTlJIHyKHDe8MBPANsxagaGkTp3M8afOJ4GnLWQiCsOBUq2BuoWPJHtOS1hZR_5D8M4n8tQIOSX7mzMtV8-NAt0OyoXKpdY9HlF1csYJJW8vpard28cRxMj0cc_YOeNeiKAw2J6OFice2nZ9wrxDrdkO9RsoESjhNVOy612aodr08mWCUlb802Rb8MNOOQz01QRS4wePCKB4cY3J47kYROfSQ6rgTWXVHJpUTIfokhXSiBSBq_pvEAIQ5Kj2z-idrfAWmdzQuBuj4SDn8ef_qmU_qlieMW5fw6YssWtl9Sg3-OucbwDjr8BjN_EmaGtQMRlDYxW48t8E8yFzNrze3vGLVHJocHETjK7SRPnQmhW5FlOOdo_ByQ9zlm9AWP0t8HJ8G-w-rstMTF8OoP0B86Q1SEDxedcMkr2Crg59IjjcAMYLgZNtYxW0ynXdC78DE_-xAt4iUF0hkVnHbViT8as4RLeUEdDbORpwNlJNNcO3OOce7AKWauvx6XEOEtoxma_FFHRCV6xUuO1vYV9qyL0bprjpKEg_5Lgl045Hrj52TRTMNlL2K0oCTh8VqJAzTGT3bn6bFYhSKfjZO9vhVZTNEC85aHosM64Y4HbEoJNRgcHLGlc3kjGHBqjcxyEFDzn5nqmfRZvF7L4AaVGyTh_YlBUU5g01vq-zxpo8Pg7-h0E8FQhYUGg0AiXoPY9dFZ4v32tE0FaW72gIMOcEFgqrTvR9_9RA1o6xhdHv0O0Plpv1TYYvfzywoiov6xn1yxGSr83fm6PxHDTOVHhuaDfQNkTAvfnczT4NdxC-zWc4JnGshfxAQ3eNq0XhsL4IupKXWTmd9bcqa-g7QY2iJ1IpbVT7AltogPvF8SmFRdpEn7QXCNHK-zlUTq6tro6RSBvBbKECXy-WxK7mWABDL9SN1CjZqfNqp9ra7d9vEqIliCdEBv-fvmUy_qAdaYeFsH3KpzCrE2i1lKH0WmF_BF5zoFKO90pqfbnY3i5YugbYoGsY9gZJkdFAajU8X-uOpYyJ4Tkvtb1WUENcxgDtuVa";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127185L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }

        [Test]
        public void ShouldDecode_v_5_0201M_OpenSSL_GCM_msgpack_payload()
        {
            string key = "/rwg5qCs8UCp3Lk5QGVhc7thaJR0w0lVv7g5xTlpAZE=";
            string signature =
                    "BQMgAAAAAAAB8P4BAplFo-fjHfsaXvT9I2uA8L46zTY3SdNkrm5hJfTzS9cLmYMblwNkNa9kSUlLJtvuzVYA7TnMzSSBXff0VRiY_8d3XSUBPtQagIfIeCZO-BD_XohpYv3DvJuSn63IRACPfRPyNa7YEqPE9VK6psOIR7VUVTRY_tIsWzw51eO_KSyZaAF6ERVB2IRHFE2OmauneE2kjW4U15ib9d7d6lk-fMqKsw_c1RHEUkT3NvSNKw1l02Go2AExf20awzGip2yPlZkikXUQhuZdgLN3Yd6BIV48Bs_VzYezxnL9T2ZliRe6N-6t3SqCy03S3nQWrd11q8gTR1zea130DQwazoXYQmikTamNYBXIuaDt0NZYKL31J1XV_rAM0P1gqKxwgX4LwjzSpZW2FCqNHHj_7evmLDjZjIgY3Urwpd3cjXjDKByLj3kCa4X_hTyAmSVTQ5Q_gTUIMRQisaVobghyZSiEDzkFxSqlZoecehqI_59eWollVuUbgg3yA-8A1UYs88RxkXtWdZnBbiLDiZp7Z6tH_0IYl37Vwk3d2-nqCyv9Q9Q696-skuZ6IMF4fyDZBT81Elo47hgrBh6We0DNsJE3TKMAW5YY2suhpZYVNIx2mUALcYwCKS349iYgZEa_dcLDZ84S4cobj7jm6kutjS2Z6zAwXgqH_u1FPmiCPw2RjNp9E26sr53ZUxkUEjwzHIsLtk-Cj9T9mMt5yivEFWuOBDC_WQMkiWZO3D7mBQueCIurIsSutduYXo0sY9uKOnciqH8d56E_c8tZWt_xCNYRPO6mb691YTthylw22dzy8QFITZqF_LEtYaCqUKY5S7yS5_fYzYOTcMSwI-flOtOd0glyYW0j16T31lH80O6apt6OvPDxDWSheYVoZKLyexk2ioSEm0HSKoDRUZZSUsISOJTMlgzg8NqJQeSw8hDutWy1D5z3q_Wj4E8XjkUGMs89oTCGzGgH2vxopHGjAaj6GVFyYImkUYbqKe9vudtGCdj7xqJXGy9V6-RelyE2OgblzGdsUAwH6KlwBSuY7J0lK9FxMsBlp_FXdFpBsQukDQ";
            string userAgent =
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            List<string> ipAddresses = ["176.103.168.22"];

            var verify = Signature5Verifier.Verify(signature, userAgent, key, ipAddresses);

            Assert.That(verify.ZoneId, Is.EqualTo(127230L));
            Assert.That(verify.Gpu, Is.EqualTo("NVIDIA/GeForce GTX 1660 Ti"));
            Assert.That(verify.TrueUa, Is.EqualTo("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 TrueUA (Desktop)"));
            Assert.That(verify.Verdict, Is.EqualTo("bot"));
            Assert.That(verify.Result, Is.EqualTo(9));
            Assert.IsNull(verify.AdditionalData);
        }
    }
}