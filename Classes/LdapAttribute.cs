using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Ldap
{
    public class LdapAttribute
    {
        public Tag Tag;
        public Byte[] Value;


        public LdapAttribute()
        {

        }


        public Byte[] GetBytes()
        {
            if (Tag.IsSequence)
            {
                throw new NotImplementedException(); // todo add complex types
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
