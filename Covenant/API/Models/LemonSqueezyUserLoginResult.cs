// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace LemonSqueezy.API.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    public partial class LemonSqueezyUserLoginResult
    {
        /// <summary>
        /// Initializes a new instance of the LemonSqueezyUserLoginResult class.
        /// </summary>
        public LemonSqueezyUserLoginResult()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the LemonSqueezyUserLoginResult class.
        /// </summary>
        public LemonSqueezyUserLoginResult(bool? success = default(bool?), string covenantToken = default(string))
        {
            Success = success;
            LemonSqueezyToken = covenantToken;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "success")]
        public bool? Success { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "covenantToken")]
        public string LemonSqueezyToken { get; set; }

    }
}