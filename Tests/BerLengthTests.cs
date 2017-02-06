using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections;

namespace Flexinets.Ldap.Tests
{
    [TestClass]
    public class BerLengthTests
    {
        [TestMethod]
        public void TestBerLengthShortNotation1()
        {
            var berlength = Utils.IntToBerLength(1);
            Assert.AreEqual("10000000", Utils.BitsToString(new BitArray(berlength)));
        }


        [TestMethod]
        public void TestBerLengthShortNotation2()
        {
            var berlength = Utils.IntToBerLength(127);
            Assert.AreEqual("11111110", Utils.BitsToString(new BitArray(berlength)));
        }


        [TestMethod]
        public void TestBerLengthLongNotation1()
        {
            var berlength = Utils.IntToBerLength(128);
            Assert.AreEqual("10000001 00000001", Utils.BitsToString(new BitArray(berlength)));
        }


        [TestMethod]
        public void TestBerLengthLongNotation2()
        {
            var berlength = Utils.IntToBerLength(256);
            Assert.AreEqual("01000001 00000000 10000000", Utils.BitsToString(new BitArray(berlength)));
        }


        [TestMethod]
        public void TestBerLengthLongNotation3()
        {
            var berlength = Utils.IntToBerLength(65536);
            Assert.AreEqual("11000001 00000000 00000000 10000000", Utils.BitsToString(new BitArray(berlength)));
        }


        [TestMethod]
        public void TestBerLengthLongNotation4()
        {
            var berlength = Utils.IntToBerLength(255);
            Assert.AreEqual("10000001 11111111", Utils.BitsToString(new BitArray(berlength)));
        }
    }
}
