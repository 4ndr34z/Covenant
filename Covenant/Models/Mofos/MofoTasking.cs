// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;

using LemonSqueezy.Core;
using LemonSqueezy.Models.LemonSqueezy;

namespace LemonSqueezy.Models.Mofos
{
    public class CommandOutput
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        public string Output { get; set; } = "";

        [Required]
        public int MofoCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public MofoCommand MofoCommand { get; set; }
    }

    public class MofoCommand
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Command { get; set; }
        [Required]
        public DateTime CommandTime { get; set; } = DateTime.MinValue;
        [Required]
        public int CommandOutputId { get; set; }
        public CommandOutput CommandOutput { get; set; }

        [Required]
        public string UserId { get; set; }
        public LemonSqueezyUser User { get; set; }

        public int? MofoTaskingId { get; set; } = null;
        public MofoTasking MofoTasking { get; set; }

        public int MofoId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Mofo Mofo { get; set; }
    }

    public enum MofoTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public enum MofoTaskingType
    {
        Assembly,
        SetDelay,
        SetJItter,
        SetConneCTAttEmpts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill
    }

    public class MofoTasking
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public int MofoId { get; set; }
        public Mofo Mofo { get; set; }
        [Required]
        public int MofoTaskId { get; set; }
        public MofoTask MofoTask { get; set; }

        public MofoTaskingType Type { get; set; } = MofoTaskingType.Assembly;
        public List<string> Parameters { get; set; } = new List<string>();

        public MofoTaskingStatus Status { get; set; } = MofoTaskingStatus.Uninitialized;
        public DateTime TaskingTime { get; set; } = DateTime.MinValue;
        public DateTime CompletionTime { get; set; } = DateTime.MinValue;

        public int MofoCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public MofoCommand MofoCommand { get; set; }
    }
}
