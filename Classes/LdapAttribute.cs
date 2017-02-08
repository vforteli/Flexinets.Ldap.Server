using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Ldap
{
    public class LdapAttribute
    {
        public Tag Tag;
        public Byte[] Value = new byte[0];
        public List<LdapAttribute> ChildAttributes = new List<LdapAttribute>();


        public LdapAttribute()
        {

        }


        /// <summary>
        /// Parse an ldap packet from a byte array. Assumed to be the complete packet
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static LdapAttribute ParsePacket(Byte[] bytes)
        {
            return ParseAttributes(bytes, 0, null)[0];
        }


        /// <summary>
        /// Parse the child attributes
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="currentPosition"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        private static List<LdapAttribute> ParseAttributes(Byte[] bytes, Int32 currentPosition, Int32? length)
        {
            var list = new List<LdapAttribute>();
            while (!length.HasValue || (currentPosition < length))
            {
                var tag = Tag.Parse(bytes[currentPosition]);
                currentPosition++;
                int i;
                var attributeLength = Utils.BerLengthToInt(bytes, currentPosition, out i);                
                currentPosition += i;

                if (!length.HasValue)
                {
                    length = attributeLength + currentPosition;
                }

                var attribute = new LdapAttribute { Tag = tag };
                if (tag.IsSequence)
                {
                    attribute.ChildAttributes = ParseAttributes(bytes, currentPosition, length);
                }
                else
                {
                    attribute.Value = new Byte[attributeLength];
                    Buffer.BlockCopy(bytes, currentPosition, attribute.Value, 0, attributeLength);
                }
                list.Add(attribute);

                currentPosition += attributeLength;
            }
            return list;
        }


        /// <summary>
        /// Get the byte representation of the packet
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes()
        {
            if (Tag.IsSequence)
            {
                var list = new List<Byte>();
                foreach (var attribute in ChildAttributes)
                {
                    list.AddRange(attribute.GetBytes().ToList());
                }

                var lengthbytes = Utils.IntToBerLength(list.Count);
                var attributeBytes = new byte[1 + lengthbytes.Length + list.Count];
                attributeBytes[0] = Tag.GetTagByte();
                Buffer.BlockCopy(lengthbytes, 0, attributeBytes, 1, lengthbytes.Length);
                Buffer.BlockCopy(list.ToArray(), 0, attributeBytes, 1 + lengthbytes.Length, list.Count);
                return attributeBytes;
            }
            else
            {
                var lengthbytes = Utils.IntToBerLength(Value.Length);
                var attributeBytes = new byte[1 + lengthbytes.Length + Value.Length];
                attributeBytes[0] = Tag.GetTagByte();
                Buffer.BlockCopy(lengthbytes, 0, attributeBytes, 1, lengthbytes.Length);
                Buffer.BlockCopy(Value, 0, attributeBytes, 1 + lengthbytes.Length, Value.Length);
                return attributeBytes;
            }
        }
    }
}
