using System;
using System.Collections;
using System.Text;
using System.Linq;


namespace Flexinets.Ldap
{
    public static class Utils
    {
        public static Byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static String ByteArrayToString(byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }


        /// <summary>
        /// Used for debugging and testing...
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static String BitsToString(BitArray bits)
        {
            int i = 1;
            var derp = "";
            foreach (var bit in bits)
            {
                derp += Convert.ToInt32(bit);
                if (i % 8 == 0)
                {
                    derp += " ";
                }
                i++;
            }
            return derp.Trim();
        }


        /// <summary>
        /// Convert integer length to a byte array with BER encoding
        /// https://en.wikipedia.org/wiki/X.690#BER_encoding
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static Byte[] IntToBerLength(Int32 length)
        {
            // Short notation
            if (length <= 127)
            {
                return new byte[] { (byte)length };
            }
            // Long notation
            else
            {
                var intbytes = BitConverter.GetBytes(length);

                byte intbyteslength = (byte)intbytes.Length;

                // Get the actual number of bytes needed
                while (intbyteslength >= 0)
                {
                    intbyteslength--;
                    if (intbytes[intbyteslength - 1] != 0)
                    {
                        break;
                    }
                }

                var lengthByte = intbyteslength + 128;
                var berBytes = new byte[1 + intbyteslength];
                berBytes[0] = (byte)lengthByte;
                Buffer.BlockCopy(intbytes, 0, berBytes, 1, intbyteslength);
                return berBytes;
            }
        }


        /// <summary>
        /// Gets the integer length from a BER encoded byte array at the current position
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="currentPosition"></param>
        /// <param name="position"></param>
        /// <returns></returns>
        public static Int32 BerLengthToInt(Byte[] bytes, Int32 currentPosition, out Int32 position)
        {
            position = 1;   // The minimum length of a ber encoded length is 1 byte
            int attributeLength = 0;
            if (bytes[currentPosition] >> 7 == 1)    // Long notation
            {
                var lengthoflengthbytes = bytes[currentPosition] & 127;
                var lengthBytes = new Byte[4];
                Buffer.BlockCopy(bytes, currentPosition + 1, lengthBytes, 0, lengthoflengthbytes);
                attributeLength = BitConverter.ToInt32(lengthBytes.Reverse().ToArray(), 0);
                position += lengthoflengthbytes;
            }
            else // Short notation
            {
                attributeLength = bytes[currentPosition] & 127;
            }

            return attributeLength;
        }
    }
}
