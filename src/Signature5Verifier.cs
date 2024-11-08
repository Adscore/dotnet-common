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
using AdScore.Signature.Verification.V5;

namespace AdScore.Signature
{
    /**
     * Entry point of AdScore signature v5 verification library. It expose verify method allowing to verify
     * AdScore signature against given set of ipAddress(es) for given zone.
     *
     * V5 is in fact an encrypted payload containing various metadata about the traffic.
     * Its decryption does not rely on IP address nor User Agent string,
     * so it is immune for environment changes usually preventing V4 to be even decoded.
     * result is also included in the payload, but client doing the integration can make its own decision basing on the metadata accompanying.
     *
     */
    public class Signature5Verifier
    {

        /**
         * Verifies the signature against the provided user agent, key, and IP addresses.
         *
         * @param signature The string which we want to verify.
         * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'.
         * @param key "Zone Response Key" which you might find in "Zone Encryption" page.
         * @param ipAddresses List of strings containing IPv4 or IPv6 addresses against which we check signature.
         *                    Usually fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses header.
         *                    All possible IP addresses may be provided at once; the verifier returns a list of chosen
         *                    IP addresses that matched with the signature.
         * @return Signature5VerificationResult object representing the result of the signature verification.
         * @throws VersionError If there is an error related to version parsing or compatibility.
         * @throws ParseError If there is an error parsing the signature or during decryption process
         * @throws VerifyError If there is an error during verify decrypted Signature
         */
        public static Signature5VerificationResult Verify(
                string signature,
                string userAgent,
                string key,
                List<string> ipAddresses)
        {
            return new Signature5VerifierService().CreateFromRequest(signature, userAgent, key, ipAddresses);
        }
    }
}
