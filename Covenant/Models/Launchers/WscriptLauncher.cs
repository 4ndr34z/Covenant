﻿// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Linq;
using Microsoft.CodeAnalysis;

using LemonSqueezy.Models.Listeners;

namespace LemonSqueezy.Models.Launchers
{
    public class WscriptLauncher : ScriptletLauncher
    {
        public WscriptLauncher()
        {
            this.Name = "Wscript";
            this.Type = LauncherType.Wscript;
            this.Description = "Uses wscript.exe to launch a Mofo using a COM activated Delegate and ActiveXObjects (ala DotNetToJScript). Please note that DotNetToJScript-based launchers may not work on Windows 10 and Windows Server 2016.";
            this.ScriptType = ScriptletType.Plain;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        protected override string GetLauncher()
        {
            string launcher = "wscript" + " " + "file.js";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string launcher = "wscript" + " " + hostedFile.Path.Split('/').Last();
                this.LauncherString = launcher;
                return launcher;
            }
            return "";
        }
    }
}