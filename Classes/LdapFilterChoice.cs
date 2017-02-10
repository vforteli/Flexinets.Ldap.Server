namespace Flexinets.Ldap
{
    public enum LdapFilterChoice
    {
        and = 0,
        or = 1,
        not = 2,
        equalityMatch = 3,
        substrings = 4,
        greaterOrEqual = 5,
        lessOrEqual = 6,
        present = 7,
        approxMatch = 8,
        extensibleMatch = 9,
    }
}
