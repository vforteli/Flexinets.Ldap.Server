using System;
using System.Collections;

namespace Flexinets.Ldap
{

    public class Tag
    {
        private Byte _tagByte;
        private TagType _tagType;
        private Boolean _isSequence;
        private Byte _data;


        /// <summary>
        /// Create a tag with an ldap operation
        /// </summary>
        /// <param name="type"></param>
        /// <param name="isSequence"></param>
        /// <param name="operation"></param>
        public Tag(TagType type, Boolean isSequence, LdapOperation operation)
        {
            _tagType = type;
            _isSequence = isSequence;
            _data = (byte)operation;
        }


        /// <summary>
        /// Create a tag with universal data type
        /// </summary>
        /// <param name="type"></param>
        /// <param name="isSequence"></param>
        /// <param name="dataType"></param>
        public Tag(TagType type, Boolean isSequence, UniversalDataType dataType)
        {
            _tagType = type;
            _isSequence = isSequence;
            _data = (byte)dataType;
        }


        /// <summary>
        /// Gets the tag as a byte that can be added to the packet
        /// </summary>
        /// <returns></returns>
        public Byte GetTagByte()
        {
            var foo = _data + (Convert.ToByte(_isSequence) << 5) + ((byte)_tagType << 6);            
            return (byte)foo;
        }


        private Tag(Byte tagByte)
        {
            _tagByte = tagByte;
        }


        /// <summary>
        /// Parses a raw tag byte
        /// </summary>
        /// <param name="tagByte"></param>
        /// <returns></returns>
        public static Tag Parse(Byte tagByte)
        {
            return new Tag(tagByte);
        }

        public Boolean IsSequence
        {
            get { return new BitArray(new byte[] { _tagByte }).Get(5); }    // todo endianess...
        }

        public TagType TagType
        {
            // todo fix...
            get
            {
                var foo = new BitArray(new byte[] { _tagByte }).Get(6);
                var bar = new BitArray(new byte[] { _tagByte }).Get(7);
                if (!foo && !bar)
                {
                    return TagType.Universal;
                }
                if (bar && !foo)
                {
                    return TagType.Context;
                }
                else
                {
                    return TagType.Application;
                }
            }
        }


        public UniversalDataType DataType
        {
            get
            {
                return (UniversalDataType)GetTagType(_tagByte);
            }
        }


        public LdapOperation LdapOperation
        {
            get
            {
                return (LdapOperation)GetTagType(_tagByte);
            }
        }


        private Byte GetTagType(Byte tagByte)
        {
            var bits = new BitArray(new byte[] { _tagByte });
            bits.Set(5, false);
            bits.Set(6, false);
            bits.Set(7, false);
            byte[] bytes = new byte[1];
            bits.CopyTo(bytes, 0);
            return bytes[0];
        }
    }
}
