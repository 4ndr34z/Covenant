// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;

namespace LemonSqueezy.Models.LemonSqueezy
{
    public class LemonSqueezyUser : IdentityUser
    {
        public LemonSqueezyUser() : base()
        {
            this.Email = "";
            this.NormalizedEmail = "";
            this.PhoneNumber = "";
            this.LockoutEnd = DateTime.UnixEpoch;
            this.ThemeId = 1;
        }

        public int ThemeId { get; set; }
        public Theme Theme { get; set; }
    }

    public class LemonSqueezyUserLogin
    {
        public string Id { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }

    public class LemonSqueezyUserRegister : LemonSqueezyUserLogin
    {
        [Required]
        public string ConfirmPassword { get; set; }
    }

    public class LemonSqueezyUserLoginResult
    {
        public bool Success { get; set; } = true;
        public string LemonSqueezyToken { get; set; } = default;
    }
}
