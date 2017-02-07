using System;
using System.Collections;

namespace Flexinets.Ldap
{

    public class Tag
    {
        private Byte _tagByte;


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


        /// <summary>
        /// Create an application tag
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="isSequence"></param>
        public Tag(LdapOperation operation, Boolean isSequence)
        {
            _tagByte = (byte)((byte)operation + (Convert.ToByte(isSequence) << 5) + ((byte)TagType.Application << 6));
        }


        /// <summary>
        /// Create a universal tag
        /// </summary>
        /// <param name="isSequence"></param>
        /// <param name="operation"></param>
        public Tag(UniversalDataType dataType, Boolean isSequence)
        {
            _tagByte = (byte)((byte)dataType + (Convert.ToByte(isSequence) << 5) + ((byte)TagType.Universal << 6));
        }


        /// <summary>
        /// Create a context tag
        /// </summary>
        /// <param name="isSequence"></param>
        /// <param name="operation"></param>
        public Tag(Boolean isSequence, Byte context)
        {
            _tagByte = (byte)((byte)context + (Convert.ToByte(isSequence) << 5) + ((byte)TagType.Context << 6));
        }


        /// <summary>
        /// Gets the tag as a byte that can be added to the packet
        /// </summary>
        /// <returns></returns>
        public Byte GetTagByte()
        {
            return _tagByte;
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


        private Tag(Byte tagByte)
        {
            _tagByte = tagByte;
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
