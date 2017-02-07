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


        [TestMethod]
        public void TestLdapAttributeSequenceGetBytesString()
        {
            var packet = new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, true, UniversalDataType.Sequence)
            };
            packet.ChildAttributes.Add(new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Integer),
                Value = new Byte[] { 1 }
            });

            // Bind request
            var bindrequest = new LdapAttribute { Tag = new Tag(TagType.Application, true, LdapOperation.BindRequest) };
            bindrequest.ChildAttributes.Add(new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.Integer),
                Value = new Byte[] { 3 }    // version 3
            });
            bindrequest.ChildAttributes.Add(new LdapAttribute
            {
                Tag = new Tag(TagType.Universal, false, UniversalDataType.OctetString),
                Value = Encoding.UTF8.GetBytes("cn=bindUser,cn=Users,dc=dev,dc=company,dc=com")
            });
            bindrequest.ChildAttributes.Add(new LdapAttribute
            {
                Tag = new Tag(TagType.Context, false, (UniversalDataType)0),
                Value = Encoding.UTF8.GetBytes("bindUserPassword")
            });

            packet.ChildAttributes.Add(bindrequest);


            var expected = "30490201016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264";
            Assert.AreEqual(expected, Utils.ByteArrayToString(packet.GetBytes()));
        }
    }
}
