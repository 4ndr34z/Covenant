// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using LemonSqueezy.Core;
using LemonSqueezy.Models.Listeners;

namespace LemonSqueezy.Models.Mofos
{
    public enum MofoStatus
    {
        Uninitialized,
        Stage0,
        Stage1,
        Stage2,
        Active,
        Lost,
        Exited,
        Disconnected,
        Hidden
    }

    public enum IntegrityLevel
    {
        Untrusted,
        Low,
        Medium,
        High,
        System
    }

    public class Mofo
    {
        // Information to uniquely identify this Mofo
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public string OriginalServerGuid { get; set; } = Utilities.CreateShortGuid();
        [DisplayName("SOMEID")]
        public string SOMEID { get; set; }

        // Downstream Mofo SOMEIDs
        public List<string> Children { get; set; } = new List<string>();

        // Communication information
        [Required]
        public int ImplantTemplateId { get; set; }
        public ImplantTemplate ImplantTemplate { get; set; }
        [Required]
        public bool ValCerT { get; set; } = true;
        [Required]
        public bool UsCertPin { get; set; } = true;
        [Required, DisplayName("SMBPipeName")]
        public string SMBPipeName { get; set; } = "mofosvc";

        // Information about the Listener
        public int ListenerId { get; set; }
        public Listener Listener { get; set; }

        // Settings that can be configured
        public string Note { get; set; } = "";
        [Required, Range(0, int.MaxValue)]
        public int Delay { get; set; } = 10;
        [Required, Range(0, 100)]
        public int JItterPercent { get; set; } = 10;
        [Required, Range(0, int.MaxValue)]
        public int ConneCTAttEmpts { get; set; } = 5000;
        [Required]
        public DateTime KillDate { get; set; } = DateTime.MaxValue;

        // Attributes of the remote Mofo
        [Required]
        public Common.DotNetVersion DotNetVersion { get; set; } = Common.DotNetVersion.Net35;
        [Required]
        public Compiler.RuntimeIdentifier RuntimeIdentifier { get; set; } = Compiler.RuntimeIdentifier.win_x64;
        [Required]
        public MofoStatus Status { get; set; } = MofoStatus.Uninitialized;
        [Required]
        public IntegrityLevel Integrity { get; set; } = IntegrityLevel.Untrusted;
        public string Process { get; set; } = "";
        public string UserDomainName { get; set; } = "";
        public string UserName { get; set; } = "";
        [DisplayName("IPAddress")]
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string OperatingSystem { get; set; } = "";

        // Information used for authentication or encrypted key exchange
        public string MofoSharedSecretPassword { get; set; } = Utilities.CreateSecretPassword();
        public string MofoRSAPublicKey { get; set; } = "";
        public string MofoNegotiatedSessKEy { get; set; } = "";
        public string MofoChallenge { get; set; } = "";

        // Time information
        public DateTime ActivationTime { get; set; } = DateTime.MinValue;
        public DateTime LastCheckIn { get; set; } = DateTime.MinValue;

        public string PowerShellImport { get; set; } = "";
        public List<MofoCommand> MofoCommands { get; set; } = new List<MofoCommand>();

        public void AddChild(Mofo mofo)
        {
            if (!string.IsNullOrWhiteSpace(mofo.SOMEID))
            {
                this.Children.Add(mofo.SOMEID);
            }
        }

        public bool RemoveChild(Mofo mofo)
        {
            return this.Children.Remove(mofo.SOMEID);
        }
    }
}
