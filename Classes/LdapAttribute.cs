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
        public Byte[] Value = new byte[0];
        public List<LdapAttribute> ChildAttributes = new List<LdapAttribute>();


        public LdapAttribute()
        {

        }


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
