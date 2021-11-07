using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.Extensions.Configuration;

using LemonSqueezy.API;
using LemonSqueezy.Models.Listeners;

namespace LemonSqueezy.Core
{
    public class LemonSqueezyAPIService
    {
        private readonly LemonSqueezyAPI _client;

        public LemonSqueezyAPIService(IConfiguration configuration)
        {
            X509Certificate2 covenantCert = new X509Certificate2(Common.LemonSqueezyPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == covenantCert.GetCertHashString();
                }
            };
            _client = new LemonSqueezyAPI(
                new Uri("https://localhost:" + configuration["LemonSqueezyPort"]),
                new TokenCredentials(configuration["ServiceUserToken"]),
                clientHandler
            );
        }

        public async Task CreateHttpListener(HttpListener listener)
        {
            await _client.CreateHttpListenerAsync(ToAPIListener(listener));
        }

        public async Task CreateBridgeListener(BridgeListener listener)
        {
            await _client.CreateBridgeListenerAsync(ToAPIListener(listener));
        }

        public static LemonSqueezy.API.Models.HttpListener ToAPIListener(HttpListener listener)
        {
            return new LemonSqueezy.API.Models.HttpListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                LemonSqueezyUrl = listener.LemonSqueezyUrl,
                LemonSqueezyToken = listener.LemonSqueezyToken,
                Description = listener.Description,
                Guid = listener.SOMEID,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                SslCertHash = listener.SSLCertHash,
                SslCertificate = listener.SSLCertificate,
                SslCertificatePassword = listener.SSLCertificatePassword,
                StartTime = listener.StartTime,
                Status = (LemonSqueezy.API.Models.ListenerStatus)Enum.Parse(typeof(LemonSqueezy.API.Models.ListenerStatus), listener.Status.ToString(), true),
                Urls = listener.Urls,
                UseSSL = listener.UseSSL
            };
        }

        public static LemonSqueezy.API.Models.BridgeListener ToAPIListener(BridgeListener listener)
        {
            return new LemonSqueezy.API.Models.BridgeListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                LemonSqueezyUrl = listener.LemonSqueezyUrl,
                LemonSqueezyToken = listener.LemonSqueezyToken,
                Description = listener.Description,
                Guid = listener.SOMEID,
                IsBridgeConnected = listener.IsBridgeConnected,
                ImplantReadCode = listener.ImplantReadCode,
                ImplantWriteCode = listener.ImplantWriteCode,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                StartTime = listener.StartTime,
                Status = (LemonSqueezy.API.Models.ListenerStatus)Enum.Parse(typeof(LemonSqueezy.API.Models.ListenerStatus), listener.Status.ToString(), true)
            };
        }
    }
}