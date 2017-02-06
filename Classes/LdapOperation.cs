namespace Flexinets.Ldap
{
    // Ldap operations from https://tools.ietf.org/html/rfc4511#section-4.2
    public enum LdapOperation
    {
        BindRequest = 0,
        BindResponse = 1,
        UnbindRequest = 2,
        SearchRequest = 3,
        SearchResultEntry = 4,
        SearchResultDone = 5,
        SearchResultReference = 6
        // todo add rest if needed...
    }
}
