using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;

using LemonSqueezy.Hubs;
using LemonSqueezy.Models.LemonSqueezy;
using LemonSqueezy.Models.Listeners;
using LemonSqueezy.Models.Launchers;
using LemonSqueezy.Models.Mofos;
using LemonSqueezy.Models.Indicators;

namespace LemonSqueezy.Core
{
    public interface ILemonSqueezyUserNotificationService
    {
        event EventHandler<LemonSqueezyUser> OnCreateLemonSqueezyUser;
        event EventHandler<LemonSqueezyUser> OnEditLemonSqueezyUser;
        event EventHandler<string> OnDeleteLemonSqueezyUser;
        Task NotifyCreateLemonSqueezyUser(object sender, LemonSqueezyUser user);
        Task NotifyEditLemonSqueezyUser(object sender, LemonSqueezyUser user);
        Task NotifyDeleteLemonSqueezyUser(object sender, string id);
    }

    public interface IIdentityRoleNotificationService
    {
        event EventHandler<IdentityRole> OnCreateIdentityRole;
        event EventHandler<IdentityRole> OnEditIdentityRole;
        event EventHandler<string> OnDeleteIdentityRole;
    }

    public interface IIdentityUserRoleNotificationService
    {
        event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole;
        event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole;
        event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole;
    }

    public interface IThemeNotificationService
    {
        event EventHandler<Theme> OnCreateTheme;
        event EventHandler<Theme> OnEditTheme;
        event EventHandler<int> OnDeleteTheme;
        Task NotifyCreateTheme(object sender, Theme theme);
        Task NotifyEditTheme(object sender, Theme theme);
        Task NotifyDeleteTheme(object sender, int id);
    }

    public interface IEventNotificationService
    {
        event EventHandler<Event> OnCreateEvent;
        event EventHandler<Event> OnEditEvent;
        event EventHandler<int> OnDeleteEvent;
        Task NotifyCreateEvent(object sender, Event anEvent);
    }

    public interface IImplantTemplateNotificationService
    {
        event EventHandler<ImplantTemplate> OnCreateImplantTemplate;
        event EventHandler<ImplantTemplate> OnEditImplantTemplate;
        event EventHandler<int> OnDeleteImplantTemplate;
    }

    public interface IMofoNotificationService
    {
        event EventHandler<Mofo> OnCreateMofo;
        event EventHandler<Mofo> OnEditMofo;
        event EventHandler<int> OnDeleteMofo;
        Task NotifyCreateMofo(object sender, Mofo mofo);
        Task NotifyEditMofo(object sender, Mofo mofo);
    }

    public interface IReferenceAssemblyNotificationService
    {
        event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly;
        event EventHandler<ReferenceAssembly> OnEditReferenceAssembly;
        event EventHandler<int> OnDeleteReferenceAssembly;
    }

    public interface IEmbeddedResourceNotificationService
    {
        event EventHandler<EmbeddedResource> OnCreateEmbeddedResource;
        event EventHandler<EmbeddedResource> OnEditEmbeddedResource;
        event EventHandler<int> OnDeleteEmbeddedResource;
    }

    public interface IReferenceSourceLibraryNotificationService
    {
        event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary;
        event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary;
        event EventHandler<int> OnDeleteReferenceSourceLibrary;
    }

    public interface IMofoTaskOptionNotificationService
    {
        event EventHandler<MofoTaskOption> OnCreateMofoTaskOption;
        event EventHandler<MofoTaskOption> OnEditMofoTaskOption;
        event EventHandler<int> OnDeleteMofoTaskOption;
    }

    public interface IMofoTaskNotificationService : IReferenceAssemblyNotificationService, IEmbeddedResourceNotificationService,
        IReferenceSourceLibraryNotificationService, IMofoTaskOptionNotificationService
    {
        event EventHandler<MofoTask> OnCreateMofoTask;
        event EventHandler<MofoTask> OnEditMofoTask;
        event EventHandler<int> OnDeleteMofoTask;
    }

    public interface IMofoCommandNotificationService
    {
        event EventHandler<MofoCommand> OnCreateMofoCommand;
        event EventHandler<MofoCommand> OnEditMofoCommand;
        event EventHandler<int> OnDeleteMofoCommand;
        Task NotifyCreateMofoCommand(object sender, MofoCommand command);
        Task NotifyEditMofoCommand(object sender, MofoCommand command);
    }

    public interface ICommandOutputNotificationService
    {
        event EventHandler<CommandOutput> OnCreateCommandOutput;
        event EventHandler<CommandOutput> OnEditCommandOutput;
        event EventHandler<int> OnDeleteCommandOutput;
        Task NotifyEditCommandOutput(object sender, CommandOutput output);
        Task NotifyCreateCommandOutput(object sender, CommandOutput output);
    }

    public interface IMofoTaskingNotificationService
    {
        event EventHandler<MofoTasking> OnCreateMofoTasking;
        event EventHandler<MofoTasking> OnEditMofoTasking;
        event EventHandler<int> OnDeleteMofoTasking;
        Task NotifyCreateMofoTasking(object sender, MofoTasking tasking);
        Task NotifyEditMofoTasking(object sender, MofoTasking tasking);
    }

    public interface ICredentialNotificationService
    {
        event EventHandler<CapturedCredential> OnCreateCapturedCredential;
        event EventHandler<CapturedCredential> OnEditCapturedCredential;
        event EventHandler<int> OnDeleteCapturedCredential;
    }

    public interface IIndicatorNotificationService
    {
        event EventHandler<Indicator> OnCreateIndicator;
        event EventHandler<Indicator> OnEditIndicator;
        event EventHandler<int> OnDeleteIndicator;
    }

    public interface IListenerTypeNotificationService
    {
        event EventHandler<ListenerType> OnCreateListenerType;
        event EventHandler<ListenerType> OnEditListenerType;
        event EventHandler<int> OnDeleteListenerType;
    }

    public interface IListenerNotificationService : IListenerTypeNotificationService
    {
        event EventHandler<Listener> OnCreateListener;
        event EventHandler<Listener> OnEditListener;
        event EventHandler<int> OnDeleteListener;
        event EventHandler<Mofo> OnNotifyListener;
        Task NotifyNotifyListener(object sender, Mofo mofo);
        Task NotifyCreateListener(object sender, Listener listener);
        Task NotifyEditListener(object sender, Listener listener);
    }

    public interface IProfileNotificationService
    {
        event EventHandler<Profile> OnCreateProfile;
        event EventHandler<Profile> OnEditProfile;
        event EventHandler<int> OnDeleteProfile;
    }

    public interface IHostedFileNotificationService
    {
        event EventHandler<HostedFile> OnCreateHostedFile;
        event EventHandler<HostedFile> OnEditHostedFile;
        event EventHandler<int> OnDeleteHostedFile;
    }

    public interface ILauncherNotificationService
    {
        event EventHandler<Launcher> OnCreateLauncher;
        event EventHandler<Launcher> OnEditLauncher;
        event EventHandler<int> OnDeleteLauncher;
    }

    public interface INotificationService : ILemonSqueezyUserNotificationService, IIdentityRoleNotificationService, IIdentityUserRoleNotificationService, IThemeNotificationService,
        IEventNotificationService, IImplantTemplateNotificationService, IMofoNotificationService, IMofoTaskNotificationService,
        IMofoCommandNotificationService, ICommandOutputNotificationService, IMofoTaskingNotificationService,
        ICredentialNotificationService, IIndicatorNotificationService, IListenerNotificationService, IProfileNotificationService,
        IHostedFileNotificationService, ILauncherNotificationService
    {
        
    }

    public class NotificationService : INotificationService
    {
        private readonly IHubContext<MofoHub> _mofoHub;
        private readonly IHubContext<EventHub> _eventHub;
        public NotificationService(IHubContext<MofoHub> mofohub, IHubContext<EventHub> eventhub)
        {
            _mofoHub = mofohub;
            _eventHub = eventhub;
            this.OnNotifyListener += async (sender, egressMofo) =>
            {
                await _mofoHub.Clients.Group(egressMofo.Listener.SOMEID).SendAsync("NotifyListener", egressMofo.SOMEID);
            };
            this.OnCreateEvent += async (sender, theEvent) => {
                await _eventHub.Clients.Group(theEvent.Context).SendAsync("ReceiveEvent", theEvent);
            };
        }

        public event EventHandler<LemonSqueezyUser> OnCreateLemonSqueezyUser = delegate { };
        public event EventHandler<LemonSqueezyUser> OnEditLemonSqueezyUser = delegate { };
        public event EventHandler<string> OnDeleteLemonSqueezyUser = delegate { };
        public event EventHandler<IdentityRole> OnCreateIdentityRole = delegate { };
        public event EventHandler<IdentityRole> OnEditIdentityRole = delegate { };
        public event EventHandler<string> OnDeleteIdentityRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole = delegate { };
        public event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole = delegate { };
        public event EventHandler<Theme> OnCreateTheme = delegate { };
        public event EventHandler<Theme> OnEditTheme = delegate { };
        public event EventHandler<int> OnDeleteTheme = delegate { };

        public event EventHandler<Event> OnCreateEvent = delegate { };
        public event EventHandler<Event> OnEditEvent = delegate { };
        public event EventHandler<int> OnDeleteEvent = delegate { };
        public event EventHandler<ImplantTemplate> OnCreateImplantTemplate = delegate { };
        public event EventHandler<ImplantTemplate> OnEditImplantTemplate = delegate { };
        public event EventHandler<int> OnDeleteImplantTemplate = delegate { };
        public event EventHandler<Mofo> OnCreateMofo = delegate { };
        public event EventHandler<Mofo> OnEditMofo = delegate { };
        public event EventHandler<int> OnDeleteMofo = delegate { };
        public event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly = delegate { };
        public event EventHandler<ReferenceAssembly> OnEditReferenceAssembly = delegate { };
        public event EventHandler<int> OnDeleteReferenceAssembly = delegate { };
        public event EventHandler<EmbeddedResource> OnCreateEmbeddedResource = delegate { };
        public event EventHandler<EmbeddedResource> OnEditEmbeddedResource = delegate { };
        public event EventHandler<int> OnDeleteEmbeddedResource = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary = delegate { };
        public event EventHandler<int> OnDeleteReferenceSourceLibrary = delegate { };
        public event EventHandler<MofoTaskOption> OnCreateMofoTaskOption = delegate { };
        public event EventHandler<MofoTaskOption> OnEditMofoTaskOption = delegate { };
        public event EventHandler<int> OnDeleteMofoTaskOption = delegate { };
        public event EventHandler<MofoTask> OnCreateMofoTask = delegate { };
        public event EventHandler<MofoTask> OnEditMofoTask = delegate { };
        public event EventHandler<int> OnDeleteMofoTask = delegate { };
        public event EventHandler<MofoCommand> OnCreateMofoCommand = delegate { };
        public event EventHandler<MofoCommand> OnEditMofoCommand = delegate { };
        public event EventHandler<int> OnDeleteMofoCommand = delegate { };
        public event EventHandler<CommandOutput> OnCreateCommandOutput = delegate { };
        public event EventHandler<CommandOutput> OnEditCommandOutput = delegate { };
        public event EventHandler<int> OnDeleteCommandOutput = delegate { };
        public event EventHandler<MofoTasking> OnCreateMofoTasking = delegate { };
        public event EventHandler<MofoTasking> OnEditMofoTasking = delegate { };
        public event EventHandler<int> OnDeleteMofoTasking = delegate { };
        public event EventHandler<CapturedCredential> OnCreateCapturedCredential = delegate { };
        public event EventHandler<CapturedCredential> OnEditCapturedCredential = delegate { };
        public event EventHandler<int> OnDeleteCapturedCredential = delegate { };
        public event EventHandler<Indicator> OnCreateIndicator = delegate { };
        public event EventHandler<Indicator> OnEditIndicator = delegate { };
        public event EventHandler<int> OnDeleteIndicator = delegate { };
        public event EventHandler<ListenerType> OnCreateListenerType = delegate { };
        public event EventHandler<ListenerType> OnEditListenerType = delegate { };
        public event EventHandler<int> OnDeleteListenerType = delegate { };
        public event EventHandler<Listener> OnCreateListener = delegate { };
        public event EventHandler<Listener> OnEditListener = delegate { };
        public event EventHandler<int> OnDeleteListener = delegate { };
        public event EventHandler<Mofo> OnNotifyListener = delegate { };
        public event EventHandler<Profile> OnCreateProfile = delegate { };
        public event EventHandler<Profile> OnEditProfile = delegate { };
        public event EventHandler<int> OnDeleteProfile = delegate { };
        public event EventHandler<HostedFile> OnCreateHostedFile = delegate { };
        public event EventHandler<HostedFile> OnEditHostedFile = delegate { };
        public event EventHandler<int> OnDeleteHostedFile = delegate { };
        public event EventHandler<Launcher> OnCreateLauncher = delegate { };
        public event EventHandler<Launcher> OnEditLauncher = delegate { };
        public event EventHandler<int> OnDeleteLauncher = delegate { };
        public async Task NotifyCreateLemonSqueezyUser(object sender, LemonSqueezyUser user) { await Task.Run(() => this.OnCreateLemonSqueezyUser(sender, user)); }
        public async Task NotifyEditLemonSqueezyUser(object sender, LemonSqueezyUser user) { await Task.Run(() => this.OnEditLemonSqueezyUser(sender, user)); }
        public async Task NotifyDeleteLemonSqueezyUser(object sender, string id) { await Task.Run(() => this.OnDeleteLemonSqueezyUser(sender, id)); }

        public async Task NotifyCreateTheme(object sender, Theme theme) { await Task.Run(() => this.OnCreateTheme(sender, theme)); }
        public async Task NotifyEditTheme(object sender, Theme theme) { await Task.Run(() => this.OnEditTheme(sender, theme)); }
        public async Task NotifyDeleteTheme(object sender, int id) { await Task.Run(() => this.OnDeleteTheme(sender, id)); }

        public async Task NotifyCreateEvent(object sender, Event anEvent) { await Task.Run(() => this.OnCreateEvent(sender, anEvent)); }

        public async Task NotifyCreateMofo(object sender, Mofo mofo) { await Task.Run(() => this.OnCreateMofo(sender, mofo)); }
        public async Task NotifyEditMofo(object sender, Mofo mofo) { await Task.Run(() => this.OnEditMofo(sender, mofo)); }

        public async Task NotifyCreateMofoCommand(object sender, MofoCommand command) { await Task.Run(() => this.OnCreateMofoCommand(sender, command)); }
        public async Task NotifyEditMofoCommand(object sender, MofoCommand command) { await Task.Run(() => this.OnEditMofoCommand(sender, command)); }

        public async Task NotifyCreateCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnCreateCommandOutput(sender, output)); }
        public async Task NotifyEditCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnEditCommandOutput(sender, output)); }

        public async Task NotifyCreateMofoTasking(object sender, MofoTasking tasking) { await Task.Run(() => this.OnCreateMofoTasking(sender, tasking)); }
        public async Task NotifyEditMofoTasking(object sender, MofoTasking tasking) { await Task.Run(() => this.OnEditMofoTasking(sender, tasking)); }

        public async Task NotifyNotifyListener(object sender, Mofo mofo) { await Task.Run(() => this.OnNotifyListener(sender, mofo)); }

        public async Task NotifyCreateListener(object sender, Listener listener) { await Task.Run(() => this.OnCreateListener(sender, listener)); }
        public async Task NotifyEditListener(object sender, Listener listener) { await Task.Run(() => this.OnEditListener(sender, listener)); }
    }
}