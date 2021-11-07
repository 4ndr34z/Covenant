using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

namespace LemonSqueezy.Models.Mofos
{
    public class MofoTaskOption : ISerializable<MofoTaskOption>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;

        public int MofoTaskId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public MofoTask Task { get; set; }

        internal SerializedMofoTaskOption ToSerializedMofoTaskOption()
        {
            return new SerializedMofoTaskOption
            {
                Name = this.Name,
                Value = "",
                DefaultValue = this.DefaultValue,
                Description = this.Description,
                SuggestedValues = this.SuggestedValues,
                Optional = this.Optional,
                DisplayInCommand = this.DisplayInCommand,
                FileOption = this.FileOption
            };
        }

        internal MofoTaskOption FromSerializedMofoTaskOption(SerializedMofoTaskOption option)
        {
            this.Name = option.Name;
            this.Value = option.Value;
            this.DefaultValue = option.DefaultValue;
            this.Description = option.Description;
            this.SuggestedValues = option.SuggestedValues;
            this.Optional = option.Optional;
            this.DisplayInCommand = option.DisplayInCommand;
            this.FileOption = option.FileOption;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedMofoTaskOption());
        }

        public MofoTaskOption FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedMofoTaskOption option = deserializer.Deserialize<SerializedMofoTaskOption>(yaml);
            return this.FromSerializedMofoTaskOption(option);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedMofoTaskOption());
        }

        public MofoTaskOption FromJson(string json)
        {
            SerializedMofoTaskOption option = JsonConvert.DeserializeObject<SerializedMofoTaskOption>(json);
            return this.FromSerializedMofoTaskOption(option);
        }
    }

    internal class SerializedMofoTaskOption
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;
    }
}
