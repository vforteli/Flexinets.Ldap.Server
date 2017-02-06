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


        [TestMethod]
        public void TestBerLengthLongNotation5()
        {
            var bytes = Utils.StringToByteArray("300c02010161070a010004000400");
            var position = 1;
            var intLength = Utils.BerLengthToInt(bytes, 1, out position);

            Assert.AreEqual(12, intLength);
        }


        [TestMethod]
        public void TestBerLengthLongNotation6()
        {
            var bytes = Utils.StringToByteArray("300c02010161070a010004000400");
            var position = 1;
            var intLength = Utils.BerLengthToInt(bytes, 3, out position);

            Assert.AreEqual(1, intLength);
        }
    }
}
