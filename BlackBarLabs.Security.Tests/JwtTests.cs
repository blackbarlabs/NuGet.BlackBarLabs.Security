using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Security.Claims;
using BlackBarLabs.Security.Tokens;
using System.Linq;

namespace BlackBarLabs.Security.Tests
{
    [TestClass]
    public class JwtTests
    {
        [TestMethod]
        public void CreateAndDecypherTokens()
        {
            var authId = Guid.NewGuid();
            var sessionId = Guid.NewGuid();
            var scope = new Uri("http://api.example.com/System1");

            Func<string, bool> assertFailedReturnFalse = (why) =>
            {
                Assert.Fail(why);
                return false;
            };

            var success = JwtTools.CreateToken(sessionId, authId, scope,
                TimeSpan.FromDays(1.0),
                (jwtToken) =>
                {
                    return jwtToken.ParseToken(
                        (claims) =>
                        {
                            Assert.AreEqual(sessionId, claims.GetSessionId(sId => sId));
                            Assert.AreEqual(authId, claims.GetAuthId(aId => aId));
                            return true;
                        },
                        (why) => assertFailedReturnFalse(why),
                        (setting) => assertFailedReturnFalse(setting),
                        (setting, why) => assertFailedReturnFalse(setting + ":" + why),
                        "Example.issuer",
                        "Example.key");
                },
                (setting) => assertFailedReturnFalse(setting),
                (setting, why) => assertFailedReturnFalse(setting + ":" + why),
                "Example.issuer",
                "Example.key");
            Assert.IsTrue(success);
        }

        [TestMethod]
        public void CreateRsaKeys()
        {
            var keys = Enumerable.Range(0, 10).Select(i =>
            RSA.Generate(
                (publicKey, privateKey) =>
                {
                    //Assert.Fail("public key = {0}\nprivate key = {1}", publicKey, privateKey);
                    //return true;
                    return publicKey + "  --  " + privateKey;
                }));
            var set = String.Join("\n", keys);
            Assert.Fail(set);
        }
    }
}
