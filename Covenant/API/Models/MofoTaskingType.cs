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
    /// Defines values for MofoTaskingType.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum MofoTaskingType
    {
        [EnumMember(Value = "Assembly")]
        Assembly,
        [EnumMember(Value = "SetDelay")]
        SetDelay,
        [EnumMember(Value = "SetJItter")]
        SetJItter,
        [EnumMember(Value = "SetConneCTAttEmpts")]
        SetConneCTAttEmpts,
        [EnumMember(Value = "SetKillDate")]
        SetKillDate,
        [EnumMember(Value = "Exit")]
        Exit,
        [EnumMember(Value = "Connect")]
        Connect,
        [EnumMember(Value = "Disconnect")]
        Disconnect,
        [EnumMember(Value = "Tasks")]
        Tasks,
        [EnumMember(Value = "TaskKill")]
        TaskKill
    }
    internal static class MofoTaskingTypeEnumExtension
    {
        internal static string ToSerializedValue(this MofoTaskingType? value)
        {
            return value == null ? null : ((MofoTaskingType)value).ToSerializedValue();
        }

        internal static string ToSerializedValue(this MofoTaskingType value)
        {
            switch( value )
            {
                case MofoTaskingType.Assembly:
                    return "Assembly";
                case MofoTaskingType.SetDelay:
                    return "SetDelay";
                case MofoTaskingType.SetJItter:
                    return "SetJItter";
                case MofoTaskingType.SetConneCTAttEmpts:
                    return "SetConneCTAttEmpts";
                case MofoTaskingType.SetKillDate:
                    return "SetKillDate";
                case MofoTaskingType.Exit:
                    return "Exit";
                case MofoTaskingType.Connect:
                    return "Connect";
                case MofoTaskingType.Disconnect:
                    return "Disconnect";
                case MofoTaskingType.Tasks:
                    return "Tasks";
                case MofoTaskingType.TaskKill:
                    return "TaskKill";
            }
            return null;
        }

        internal static MofoTaskingType? ParseMofoTaskingType(this string value)
        {
            switch( value )
            {
                case "Assembly":
                    return MofoTaskingType.Assembly;
                case "SetDelay":
                    return MofoTaskingType.SetDelay;
                case "SetJItter":
                    return MofoTaskingType.SetJItter;
                case "SetConneCTAttEmpts":
                    return MofoTaskingType.SetConneCTAttEmpts;
                case "SetKillDate":
                    return MofoTaskingType.SetKillDate;
                case "Exit":
                    return MofoTaskingType.Exit;
                case "Connect":
                    return MofoTaskingType.Connect;
                case "Disconnect":
                    return MofoTaskingType.Disconnect;
                case "Tasks":
                    return MofoTaskingType.Tasks;
                case "TaskKill":
                    return MofoTaskingType.TaskKill;
            }
            return null;
        }
    }
}