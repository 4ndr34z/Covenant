// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using LemonSqueezy.Core;
using LemonSqueezy.Models.Mofos;

namespace LemonSqueezy.Controllers
{
    [ApiController, Route("api/commands"), Authorize(Policy = "RequireJwtBearer")]
    public class MofoCommandApiController : Controller
    {
        private readonly ILemonSqueezyService _service;

        public MofoCommandApiController(ILemonSqueezyService service)
        {
            _service = service;
        }

        // GET: api/commands
        // <summary>
        // Get MofoCommands
        // </summary>
        [HttpGet(Name = "GetMofoCommands")]
        public async Task<ActionResult<IEnumerable<MofoCommand>>> GetMofoCommands()
        {
            return Ok(await _service.GetMofoCommands());
        }

        // GET: api/commands/{id}
        // <summary>
        // Get a MofoCommand
        // </summary>
        [HttpGet("{id}", Name = "GetMofoCommand")]
        public async Task<ActionResult<MofoCommand>> GetMofoCommand(int id)
        {
            try
            {
                return await _service.GetMofoCommand(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // POST api/commands
        // <summary>
        // Create a MofoCommand
        // </summary>
        [HttpPost(Name = "CreateMofoCommand"), ProducesResponseType(typeof(MofoCommand), 201)]
        public async Task<ActionResult<MofoCommand>> CreateMofoCommand([FromBody] MofoCommand mofoCommand)
        {
            try
            {
                mofoCommand.Mofo = await _service.GetMofo(mofoCommand.MofoId);
                MofoCommand createdCommand = await _service.CreateMofoCommand(mofoCommand);
                return CreatedAtRoute(nameof(GetMofoCommand), new { id = createdCommand.Id }, createdCommand);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // PUT api/commands
        // <summary>
        // Edit a MofoCommand
        // </summary>
        [HttpPut(Name = "EditMofoCommand")]
        public async Task<ActionResult<MofoCommand>> EditMofoCommand([FromBody] MofoCommand mofoCommand)
        {
            try
            {
                return await _service.EditMofoCommand(mofoCommand);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // DELETE api/commands/{id}
        // <summary>
        // Delete a MofoTasking
        // </summary>
        [HttpDelete("{id}", Name = "DeleteMofoCommand")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteMofoCommand(int id)
        {
            try
            {
                await _service.DeleteMofoCommand(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            return new NoContentResult();
        }
    }
}
