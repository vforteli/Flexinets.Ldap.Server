using System;
using System.Collections;
using System.Text;

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
        /// Used for debugging...
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static String BitsToString(BitArray bits)
        {
            var derp = "";
            foreach (var bit in bits)
            {
                derp += Convert.ToInt32(bit);
            }
            return derp;
        }
    }
}
