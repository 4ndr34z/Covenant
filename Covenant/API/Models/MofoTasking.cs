// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace LemonSqueezy.API.Models
{
    using Microsoft.Rest;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    public partial class MofoTasking
    {
        /// <summary>
        /// Initializes a new instance of the MofoTasking class.
        /// </summary>
        public MofoTasking()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the MofoTasking class.
        /// </summary>
        /// <param name="type">Possible values include: 'Assembly', 'SetDelay',
        /// 'SetJItter', 'SetConneCTAttEmpts', 'SetKillDate', 'Exit',
        /// 'Connect', 'Disconnect', 'Tasks', 'TaskKill'</param>
        /// <param name="status">Possible values include: 'Uninitialized',
        /// 'Tasked', 'Progressed', 'Completed', 'Aborted'</param>
        public MofoTasking(string name, int mofoId, int mofoTaskId, int? id = default(int?), Mofo mofo = default(Mofo), MofoTask mofoTask = default(MofoTask), MofoTaskingType? type = default(MofoTaskingType?), IList<string> parameters = default(IList<string>), MofoTaskingStatus? status = default(MofoTaskingStatus?), System.DateTime? taskingTime = default(System.DateTime?), System.DateTime? completionTime = default(System.DateTime?), int? mofoCommandId = default(int?))
        {
            Id = id;
            Name = name;
            MofoId = mofoId;
            Mofo = mofo;
            MofoTaskId = mofoTaskId;
            MofoTask = mofoTask;
            Type = type;
            Parameters = parameters;
            Status = status;
            TaskingTime = taskingTime;
            CompletionTime = completionTime;
            MofoCommandId = mofoCommandId;
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
        [JsonProperty(PropertyName = "mofoId")]
        public int MofoId { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "mofo")]
        public Mofo Mofo { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "mofoTaskId")]
        public int MofoTaskId { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "mofoTask")]
        public MofoTask MofoTask { get; set; }

        /// <summary>
        /// Gets or sets possible values include: 'Assembly', 'SetDelay',
        /// 'SetJItter', 'SetConneCTAttEmpts', 'SetKillDate', 'Exit',
        /// 'Connect', 'Disconnect', 'Tasks', 'TaskKill'
        /// </summary>
        [JsonProperty(PropertyName = "type")]
        public MofoTaskingType? Type { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "parameters")]
        public IList<string> Parameters { get; set; }

        /// <summary>
        /// Gets or sets possible values include: 'Uninitialized', 'Tasked',
        /// 'Progressed', 'Completed', 'Aborted'
        /// </summary>
        [JsonProperty(PropertyName = "status")]
        public MofoTaskingStatus? Status { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "taskingTime")]
        public System.DateTime? TaskingTime { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "completionTime")]
        public System.DateTime? CompletionTime { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "mofoCommandId")]
        public int? MofoCommandId { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (Name == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "Name");
            }
            if (Mofo != null)
            {
                Mofo.Validate();
            }
            if (MofoTask != null)
            {
                MofoTask.Validate();
            }
        }
    }
}
