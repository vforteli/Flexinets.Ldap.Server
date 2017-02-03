namespace Flexinets.Ldap
{
    // Ldap operations from https://tools.ietf.org/html/rfc4511#section-4.2
    public enum LdapOperation
    {
        BindRequest = 0,
        BindResponse = 1,
        UnbindRequest = 2,
        SearchRequest = 3,
        // todo add rest if needed...
    }
}
