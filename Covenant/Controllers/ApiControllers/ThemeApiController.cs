// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using LemonSqueezy.Core;
using LemonSqueezy.Models.LemonSqueezy;

namespace LemonSqueezy.Controllers.ApiControllers
{
    [ApiController, Route("api/themes"), Authorize(Policy = "RequireJwtBearer")]
    public class ThemeApiController : Controller
    {
        private readonly ILemonSqueezyService _service;
        private readonly UserManager<LemonSqueezyUser> _userManager;

        public ThemeApiController(ILemonSqueezyService service, UserManager<LemonSqueezyUser> userManager)
        {
            _service = service;
            _userManager = userManager;
        }

        // GET: api/themes
        // <summary>
        // Get a list of Themes
        // </summary>
        [HttpGet(Name = "GetThemes")]
        public async Task<ActionResult<IEnumerable<Theme>>> GetThemes()
        {
            return Ok(await _service.GetThemes());
        }

        // GET api/themes/{id}
        // <summary>
        // Get a Theme by id
        // </summary>
        [HttpGet("{id}", Name = "GetTheme")]
        public async Task<ActionResult<Theme>> GetTheme(int id)
        {
            try
            {
                return await _service.GetTheme(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // POST api/themes
        // <summary>
        // Create a Theme
        // </summary>
        [HttpPost(Name = "CreateTheme")]
        [ProducesResponseType(typeof(Theme), 201)]
        public async Task<ActionResult<Theme>> CreateTheme([FromBody] Theme theme)
        {
            try
            {
                Theme createdTheme = await _service.CreateTheme(theme);
                return CreatedAtRoute(nameof(GetTheme), new { id = createdTheme.Id }, createdTheme);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // PUT api/themes
        // <summary>
        // Edit a Theme
        // </summary>
        [HttpPut(Name = "EditTheme")]
        public async Task<ActionResult<Theme>> EditTheme([FromBody] Theme theme)
        {
            try
            {
                return await _service.EditTheme(theme);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // DELETE api/themes/{id}
        // <summary>
        // Delete a Theme
        // </summary>
        [HttpDelete("{id}", Name = "DeleteTheme")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteTheme(int id)
        {
            try
            {
                await _service.DeleteTheme(id);
                return new NoContentResult();
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }
    }
}