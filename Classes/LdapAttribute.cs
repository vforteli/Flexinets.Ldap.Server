using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Flexinets.Ldap
{
    public class LdapAttribute
    {
        private Tag _tag;
        public Byte[] Value = new byte[0];  // todo create typed getter and setter
        public List<LdapAttribute> ChildAttributes = new List<LdapAttribute>();

        public TagClass Class
        {
            get
            {
                return _tag.Class;
            }
        }

        public Boolean IsConstructed
        {
            get { return _tag.IsConstructed; }
        }

        public LdapOperation LdapOperation
        {
            get
            {
                if (_tag.Class == TagClass.Application)
                {
                    return _tag.LdapOperation;
                }
                throw new InvalidOperationException("Wrong attribute class for this operation");
            }
        }

        public UniversalDataType DataType
        {
            get
            {
                if (_tag.Class == TagClass.Universal)
                {
                    return _tag.DataType;
                }
                throw new InvalidOperationException("Wrong attribute class for this operation");
            }
        }

        public Byte ContextType
        {
            get
            {
                if (_tag.Class == TagClass.Context)
                {
                    return _tag.ContextType;
                }
                throw new InvalidOperationException("Wrong attribute class for this operation");
            }
        }


        /// <summary>
        /// Create an application attribute
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(LdapOperation operation, Boolean isConstructed)
        {
            _tag = new Tag(operation, isConstructed);
        }


        /// <summary>
        /// Create a universal attribute
        /// </summary>
        /// <param name="dataType"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(UniversalDataType dataType, Boolean isConstructed)
        {
            _tag = new Tag(dataType, isConstructed);
        }


        /// <summary>
        /// Create a context attribute
        /// </summary>
        /// <param name="contextType"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(Byte contextType, Boolean isConstructed)
        {
            _tag = new Tag(contextType, isConstructed);
        }


        /// <summary>
        /// Create an ldap packet attribute with message id
        /// </summary>
        /// <param name="messageId"></param>
        /// <returns></returns>
        public static LdapAttribute CreatePacket(Int32 messageId)
        {
            var packet = new LdapAttribute(UniversalDataType.Sequence, true);
            packet.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Integer, false) { Value = new Byte[] { (byte)messageId } });
            return packet;
        }


        /// <summary>
        /// Create an attribute with tag
        /// </summary>
        /// <param name="tag"></param>
        private LdapAttribute(Tag tag)
        {
            _tag = tag;
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

                // This is for the first pass, ie the packet itself when the length is unknown
                if (!length.HasValue)
                {
                    length = attributeLength + currentPosition;
                }

                var attribute = new LdapAttribute(tag);
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


        /// <summary>
        /// Get the byte representation of the packet
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes()
        {
            if (_tag.IsConstructed)
            {
                var list = new List<Byte>();
                foreach (var attribute in ChildAttributes)
                {
                    list.AddRange(attribute.GetBytes().ToList());
                }

                var lengthbytes = Utils.IntToBerLength(list.Count);
                var attributeBytes = new byte[1 + lengthbytes.Length + list.Count];
                attributeBytes[0] = _tag.GetTagByte();
                Buffer.BlockCopy(lengthbytes, 0, attributeBytes, 1, lengthbytes.Length);
                Buffer.BlockCopy(list.ToArray(), 0, attributeBytes, 1 + lengthbytes.Length, list.Count);
                return attributeBytes;
            }
            else
            {
                var lengthbytes = Utils.IntToBerLength(Value.Length);
                var attributeBytes = new byte[1 + lengthbytes.Length + Value.Length];
                attributeBytes[0] = _tag.GetTagByte();
                Buffer.BlockCopy(lengthbytes, 0, attributeBytes, 1, lengthbytes.Length);
                Buffer.BlockCopy(Value, 0, attributeBytes, 1 + lengthbytes.Length, Value.Length);
                return attributeBytes;
            }
        }


        public object GetValue()
        {
            if (_tag.Class == TagClass.Universal)
            {
                if (_tag.DataType == UniversalDataType.Boolean)
                {
                    return BitConverter.ToBoolean(Value, 0);
                }
                else if (_tag.DataType == UniversalDataType.Integer)
                {
                    var intbytes = new Byte[4];
                    Buffer.BlockCopy(Value, 0, intbytes, 4 - Value.Length, Value.Length);
                    return BitConverter.ToUInt32(intbytes.Reverse().ToArray(), 0);
                }
                else
                {
                    return Encoding.UTF8.GetString(Value, 0, Value.Length);
                }
            }
            else
            {
                // todo add rest...
                return Encoding.UTF8.GetString(Value, 0, Value.Length);
            }
        }
    }
}
