﻿// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using LemonSqueezy.Models.Listeners;
using LemonSqueezy.Models.Mofos;

namespace LemonSqueezy.Models.Launchers
{
    public class BinaryLauncher : Launcher
    {
        public BinaryLauncher()
        {
            this.Type = LauncherType.Binary;
            this.Description = "Uses a generated .NET Framework binary to launch a Mofo.";
            this.Name = "Binary";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = false;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Mofo mofo, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            this.LauncherString = template.Name + ".exe";
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
				Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }
    }
}
