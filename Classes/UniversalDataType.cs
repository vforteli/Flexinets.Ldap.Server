namespace Flexinets.Ldap
{
    // Universal data types from https://en.wikipedia.org/wiki/X.690#BER_encoding
    public enum UniversalDataType
    {
        EndOfContent = 0,
        Boolean = 1,
        Integer = 2,
        OctetString = 4,
        Enumerated = 10,
        Sequence = 16,
        // todo add rest if needed...
    }
}
