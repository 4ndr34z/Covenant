using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.CodeAnalysis;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using LemonSqueezy.Core;

namespace LemonSqueezy.Models.Mofos
{
    public class MofoTaskAuthor : ISerializable<MofoTaskAuthor>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Handle { get; set; } = "";
        public string Link { get; set; } = "";

        public List<MofoTask> MofoTasks { get; set; }

        internal SerializedMofoTaskAuthor ToSerializedMofoTaskAuthor()
        {
            return new SerializedMofoTaskAuthor
            {
                Name = this.Name,
                Handle = this.Handle,
                Link = this.Link
            };
        }

        internal MofoTaskAuthor FromSerializedMofoTaskAuthor(SerializedMofoTaskAuthor author)
        {
            this.Name = author.Name;
            this.Handle = author.Handle;
            this.Link = author.Link;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedMofoTaskAuthor());
        }

        public MofoTaskAuthor FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedMofoTaskAuthor author = deserializer.Deserialize<SerializedMofoTaskAuthor>(yaml);
            return this.FromSerializedMofoTaskAuthor(author);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedMofoTaskAuthor());
        }

        public MofoTaskAuthor FromJson(string json)
        {
            SerializedMofoTaskAuthor author = JsonConvert.DeserializeObject<SerializedMofoTaskAuthor>(json);
            return this.FromSerializedMofoTaskAuthor(author);
        }
    }

    internal class SerializedMofoTaskAuthor
    {
        public string Name { get; set; } = "";
        public string Handle { get; set; } = "";
        public string Link { get; set; } = "";
    }
}
