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
        SearchResultReference = 19,
        ModifyRequest = 6,
        ModifyResponse = 7,
        AddRequest = 8,
        AddResponse = 9,
        DelRequest = 10,
        DelResponse = 11,
        ModifyDNRequest = 12,
        ModifyDNResponse = 13,
        CompareRequest = 14,
        CompareResponse = 15,
        AbandonRequest = 16,
        ExtendedRequest = 23,
        ExtendedResponse = 24,
        IntermediateResponse = 25
    }
}
