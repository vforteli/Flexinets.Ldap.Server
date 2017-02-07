using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Text;

namespace Flexinets.Ldap.Tests
{
    [TestClass]
    public class LdapAttributeTests
    {
        [TestMethod]
        public void TestLdapAttributeGetBytes()
        {
            var attribute = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Integer),
                Value = new byte[] { 1 }
            };

            Assert.AreEqual("020101", Utils.ByteArrayToString(attribute.GetBytes()));
        }


        [TestMethod]
        public void TestLdapAttributeGetBytes2()
        {
            var attribute = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Integer),
                Value = new byte[] { 2 }
            };

            Assert.AreEqual("020102", Utils.ByteArrayToString(attribute.GetBytes()));
        }


        [TestMethod]
        public void TestLdapAttributeGetBytesBoolean()
        {
            var attribute = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Boolean),
                Value = new byte[] { 1 }
            };

            Assert.AreEqual("010101", Utils.ByteArrayToString(attribute.GetBytes()));
        }


        [TestMethod]
        public void TestLdapAttributeGetBytesBoolean2()
        {
            var attribute = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Boolean),
                Value = new byte[] { 0 }
            };

            Assert.AreEqual("010100", Utils.ByteArrayToString(attribute.GetBytes()));
        }


        [TestMethod]
        public void TestLdapAttributeGetBytesString()
        {
            var attribute = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.OctetString),
                Value = Encoding.UTF8.GetBytes("dc=karakorum,dc=net")
            };

            Assert.AreEqual("041364633d6b6172616b6f72756d2c64633d6e6574", Utils.ByteArrayToString(attribute.GetBytes()));
        }
    }
}
