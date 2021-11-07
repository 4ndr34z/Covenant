// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace LemonSqueezy.API.Models
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using System.Runtime;
    using System.Runtime.Serialization;

    /// <summary>
    /// Defines values for CredentialType.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum CredentialType
    {
        [EnumMember(Value = "Password")]
        Password,
        [EnumMember(Value = "Hash")]
        Hash,
        [EnumMember(Value = "Ticket")]
        Ticket
    }
    internal static class CredentialTypeEnumExtension
    {
        internal static string ToSerializedValue(this CredentialType? value)
        {
            return value == null ? null : ((CredentialType)value).ToSerializedValue();
        }

        internal static string ToSerializedValue(this CredentialType value)
        {
            switch( value )
            {
                case CredentialType.Password:
                    return "Password";
                case CredentialType.Hash:
                    return "Hash";
                case CredentialType.Ticket:
                    return "Ticket";
            }
            return null;
        }

        internal static CredentialType? ParseCredentialType(this string value)
        {
            switch( value )
            {
                case "Password":
                    return CredentialType.Password;
                case "Hash":
                    return CredentialType.Hash;
                case "Ticket":
                    return CredentialType.Ticket;
            }
            return null;
        }
    }
}
