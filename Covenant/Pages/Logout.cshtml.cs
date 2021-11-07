using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using LemonSqueezy.Models.LemonSqueezy;

namespace LemonSqueezy.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<LemonSqueezyUser> _signInManager;

        public LogoutModel(SignInManager<LemonSqueezyUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            await _signInManager.SignOutAsync();
            return LocalRedirect("/covenantuser/login");
        }
    }
}
