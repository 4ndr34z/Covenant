// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using LemonSqueezy.Core;
using LemonSqueezy.Models;
using LemonSqueezy.Models.LemonSqueezy;
using LemonSqueezy.Models.Mofos;
using LemonSqueezy.Models.Listeners;

namespace LemonSqueezy.Hubs
{
    [Authorize]
    public class MofoHub : Hub
    {
        private readonly ILemonSqueezyService _service;

        public MofoHub(ILemonSqueezyService service)
        {
            _service = service;
        }

        public async Task JoinGroup(string groupname)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupname);
        }

        public async Task GetMofos()
        {
            List<Mofo> mofos = (await _service.GetMofos()).Where(G => G.Status != MofoStatus.Uninitialized).ToList();
            foreach (Mofo g in mofos)
            {
                await this.Clients.Caller.SendAsync("ReceiveMofo", g.SOMEID, g.Name);
            }
        }

        public async Task GetListeners()
        {
            List<Listener> listeners = (await _service.GetListeners()).Where(L => L.Status == ListenerStatus.Active).ToList();
            foreach (Listener l in listeners)
            {
                await this.Clients.Caller.SendAsync("ReceiveListener", l.SOMEID, l.Name);
            }
        }

        public async Task GetMofoLinks()
        {
            List<Mofo> mofos = (await _service.GetMofos()).Where(G => G.Status != MofoStatus.Uninitialized && G.Children.Any()).ToList();
            foreach (Mofo g in mofos)
            {
                foreach (string child in g.Children)
                {
                    Mofo childMofo = await _service.GetMofoBySOMEID(child);
                    await this.Clients.Caller.SendAsync("ReceiveMofoLink", g.SOMEID, childMofo.SOMEID);
                }
            }
        }

        public async Task GetMofoListenerLinks()
        {
            IEnumerable<Mofo> allMofos = await _service.GetMofos();
            List<Mofo> mofos = (await _service.GetMofos())
                .Where(G => G.Status != MofoStatus.Uninitialized)
                .Where(G => !allMofos.Any(AG => AG.Children.Contains(G.SOMEID)))
                .ToList();
            foreach (Mofo g in mofos)
            {
                Listener l = await _service.GetListener(g.ListenerId);
                await this.Clients.Caller.SendAsync("ReceiveMofoListenerLink", l.SOMEID, g.SOMEID);
            }
        }

        public async Task GetInteract(string mofoName, string input)
        {
            LemonSqueezyUser user = await _service.GetUser(this.Context.UserIdentifier);
            Mofo mofo = await _service.GetMofoByName(mofoName);
            MofoCommand command = await _service.InteractMofo(mofo.Id, user.Id, input);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetCommandOutput(int id)
        {
            MofoCommand command = await _service.GetMofoCommand(id);
            command.CommandOutput ??= await _service.GetCommandOutput(command.CommandOutputId);
            command.User ??= await _service.GetUser(command.UserId);
            command.MofoTasking ??= await _service.GetMofoTasking(command.MofoTaskingId ?? default);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetSuggestions(string mofoName)
        {
            Mofo mofo = await _service.GetMofoByName(mofoName);
            List<string> suggestions = await _service.GetCommandSuggestionsForMofo(mofo);
            await this.Clients.Caller.SendAsync("ReceiveSuggestions", suggestions);
        }
    }
}
