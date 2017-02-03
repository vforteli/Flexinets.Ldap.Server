using System;
using System.Collections;

namespace Flexinets.Ldap
{

    public class Tag
    {
        private Byte _tagByte;

        public Tag(Byte tagByte)
        {
            _tagByte = tagByte;
        }

        public Boolean IsPrimitive
        {
            get { return !(new BitArray(new byte[] { _tagByte }).Get(5)); }    // todo endianess...
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
