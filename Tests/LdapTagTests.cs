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
            var tag = new Tag(UniversalDataType.Sequence, true);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("00001100", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }


        [TestMethod]
        public void TestLdapTagParse()
        {
            var tag = Tag.Parse(Utils.StringToByteArray("30")[0]);
            Assert.AreEqual(UniversalDataType.Sequence, tag.DataType);
            Assert.AreEqual(true, tag.IsConstructed);
            Assert.AreEqual(TagClass.Universal, tag.Class);
        }


        [TestMethod]
        public void TestLdapTag2()
        {
            var tag = new Tag(UniversalDataType.Integer, false);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("01000000", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }

        [TestMethod]
        public void TestLdapTagParse2()
        {
            var tag = Tag.Parse(Utils.StringToByteArray("02")[0]);
            Assert.AreEqual(UniversalDataType.Integer, tag.DataType);
            Assert.AreEqual(false, tag.IsConstructed);
            Assert.AreEqual(TagClass.Universal, tag.Class);
        }


        [TestMethod]
        public void TestLdapTag3()
        {
            var tag = new Tag(LdapOperation.SearchRequest, true);
            var tagbyte = tag.GetTagByte();
            Assert.AreEqual("11000110", Utils.BitsToString(new BitArray(new Byte[] { tagbyte })));
        }

        [TestMethod]
        public void TestLdapTagParse3()
        {
            var tag = Tag.Parse(Utils.StringToByteArray("63")[0]);
            Assert.AreEqual(LdapOperation.SearchRequest, tag.LdapOperation);
            Assert.AreEqual(true, tag.IsConstructed);
            Assert.AreEqual(TagClass.Application, tag.Class);
        }
    }
}
