using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Ldap.Tests
{
    [TestClass]
    public class LdapTagTests
    {
        [TestMethod]
        public void TestLdapTag()
        {
            var tag = new Tag(TagType.Universal, false, UniversalDataType.Sequence);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("00001100", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }


        [TestMethod]
        public void TestLdapTag2()
        {
            var tag = new Tag(TagType.Universal, true, UniversalDataType.Integer);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("01000000", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }


        [TestMethod]
        public void TestLdapTag3()
        {
            var tag = new Tag(TagType.Application, false, LdapOperation.SearchRequest);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("11000110", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }
    }
}
