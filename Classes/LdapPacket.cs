using System;
using System.Collections.Generic;

namespace Flexinets.Ldap
{
    public class LdapPacket : LdapAttribute
    {
        public Int32 MessageId
        {
            get
            {
                return ChildAttributes[0].GetValue<Int32>();
            }
        }


        /// <summary>
        /// Create a new Ldap packet with message id
        /// </summary>
        /// <param name="messageId"></param>
        public LdapPacket(Int32 messageId) : base(UniversalDataType.Sequence, true)
        {
            ChildAttributes.Add(new LdapAttribute(UniversalDataType.Integer, false, messageId));
        }


        /// <summary>
        /// Create a packet with tag
        /// </summary>
        /// <param name="tag"></param>
        private LdapPacket(Tag tag) : base(tag)
        {
        }


        /// <summary>
        /// Parse an ldap packet from a byte array. 
        /// Must be the complete packet
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static LdapPacket ParsePacket(Byte[] bytes)
        {
            return (LdapPacket)ParseAttributes(bytes, 0, null)[0];
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

                // This is for the first pass, ie the packet itself when the length is unknown
                if (!length.HasValue)
                {
                    length = attributeLength + currentPosition;
                }

                var attribute = new LdapPacket(tag);
                if (tag.IsConstructed && attributeLength > 0)
                {
                    attribute.ChildAttributes = ParseAttributes(bytes, currentPosition, currentPosition + attributeLength);
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
    }
}
