// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace LemonSqueezy.API.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    public partial class ListenerType
    {
        /// <summary>
        /// Initializes a new instance of the ListenerType class.
        /// </summary>
        public ListenerType()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ListenerType class.
        /// </summary>
        public ListenerType(int? id = default(int?), string name = default(string), string description = default(string))
        {
            Id = id;
            Name = name;
            Description = description;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public int? Id { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "description")]
        public string Description { get; set; }

    }
}
