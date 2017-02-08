using System;
using System.Collections;

namespace Flexinets.Ldap
{

    public class Tag
    {
        private Byte _tagByte;


        public Boolean IsSequence
        {
            get
            {
                return new BitArray(new byte[] { _tagByte }).Get(5);
            }
        }


        public TagType TagType
        {
            get
            {
                return (TagType)(_tagByte >> 6);
            }
        }


        public UniversalDataType DataType
        {
            get
            {
                return (UniversalDataType)(_tagByte & 31);
            }
        }


        public LdapOperation LdapOperation
        {
            get
            {
                return (LdapOperation)(_tagByte & 31);
            }
        }


        public Byte ContextType
        {
            get
            {
                return (byte)(_tagByte & 31);
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
        public Tag(Byte context, Boolean isSequence)
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
    }
}
