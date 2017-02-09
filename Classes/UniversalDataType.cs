namespace Flexinets.Ldap
{
    // Universal data types from https://en.wikipedia.org/wiki/X.690#BER_encoding
    public enum UniversalDataType
    {
        EndOfContent = 0,
        Boolean = 1,
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        ObjectDescriptor = 7,
        External = 8,
        Real = 9,
        Enumerated = 10,
        EmbeddedPDV = 11,
        UTF8String = 12,
        Relative = 13,
        Reserved = 14,
        Reserved2 = 15,
        Sequence = 16,
        Set = 17,
        NumericString = 18,
        PrintableString = 19,
        T61String = 20,
        VideotexString = 21,
        IA5String = 22,
        UTCTime = 23,
        GeneralizedTime = 24,
        GraphicString = 25,
        VisibleString = 26,
        GeneralString = 27,
        UniversalString = 28,
        CharacterString = 29,
        BMPString = 30
    }
}
