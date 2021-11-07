// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Threading.Tasks;

using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;

namespace LemonSqueezy.Hubs
{
    [Authorize]
    public class MofoCommandHub : Hub
    {
        public async Task JoinGroup(string context)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, context);
        }
    }
}
