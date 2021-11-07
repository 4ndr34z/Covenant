// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using LemonSqueezy.Core;
using LemonSqueezy.Models.Mofos;
using LemonSqueezy.Models.LemonSqueezy;

namespace LemonSqueezy.Controllers
{
    [ApiController, Route("api/mofos"), Authorize(Policy = "RequireJwtBearer")]
    public class MofoApiController : Controller
    {
        private readonly ILemonSqueezyService _service;

        public MofoApiController(ILemonSqueezyService service)
        {
            _service = service;
        }

        // GET: api/mofos
        // <summary>
        // Get a list of Mofos
        // </summary>
        [HttpGet(Name = "GetMofos")]
        public async Task<ActionResult<IEnumerable<Mofo>>> GetMofos()
        {
            return Ok(await _service.GetMofos());
        }

        // GET api/mofos/{id}
        // <summary>
        // Get a Mofo by id
        // </summary>
        [HttpGet("{id:int}", Name = "GetMofo")]
        public async Task<ActionResult<Mofo>> GetMofo(int id)
        {
            try
            {
                return await _service.GetMofo(id);
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

        // GET: api/mofos/{name}
        // <summary>
        // Get a Mofo by name
        // </summary>
        [HttpGet("{name}", Name = "GetMofoByName")]
        public async Task<ActionResult<Mofo>> GetMofoByName(string name)
        {
            try
            {
                return await _service.GetMofoByName(name);
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

        // GET api/mofos/someid/{someid}
        // <summary>
        // Get a Mofo by SOMEID
        // </summary>
        [HttpGet("someid/{someid}", Name = "GetMofoBySOMEID")]
        public async Task<ActionResult<Mofo>> GetMofoBySOMEID(string someid)
        {
            try
            {
                return await _service.GetMofoBySOMEID(someid);
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

        // GET api/mofos/originalsomeid/{serversomeid}
        // <summary>
        // Get a Mofo by OriginalServerSOMEID
        // </summary>
        [HttpGet("originalsomeid/{serversomeid}", Name = "GetMofoByOriginalServerSOMEID")]
        public async Task<ActionResult<Mofo>> GetMofoByOriginalServerSOMEID(string serversomeid)
        {
            try
            {
                return await _service.GetMofoByOriginalServerSOMEID(serversomeid);
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

        // GET api/mofos/{id}/path/{cid}
        // <summary>
        // Get a path to a child Mofo by id
        // </summary>
        [HttpGet("{id}/path/{cid}", Name = "GetPathToChildMofo")]
        public async Task<ActionResult<List<string>>> GetPathToChildMofo(int id, int cid)
        {
            try
            {
                return await _service.GetPathToChildMofo(id, cid);
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

        // GET api/mofos/{id}/outbound
        // <summary>
        // Get the outbound Mofo for a Mofo in the graph
        // </summary>
        [HttpGet("{id}/outbound", Name = "GetOutboundMofo")]
        public async Task<ActionResult<Mofo>> GetOutboundMofo(int id)
		{
			try
			{
				return await _service.GetOutboundMofo(id);
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


        // POST api/mofos
        // <summary>
        // Create a Mofo
        // </summary>
        [HttpPost(Name = "CreateMofo")]
        [ProducesResponseType(typeof(Mofo), 201)]
        public async Task<ActionResult<Mofo>> CreateMofo([FromBody]Mofo mofo)
        {
            try
            {
                Mofo createdMofo = await _service.CreateMofo(mofo);
                return CreatedAtRoute(nameof(GetMofo), new { id = createdMofo.Id }, createdMofo);
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

        // PUT api/mofos
        // <summary>
        // Edit a Mofo
        // </summary>
        [HttpPut(Name = "EditMofo")]
        public async Task<ActionResult<Mofo>> EditMofo([FromBody] Mofo mofo)
        {
            try
            {
                return await _service.EditMofo(mofo, await _service.GetCurrentUser(HttpContext.User));
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

        // DELETE api/mofos/{id}
        // <summary>
        // Delete a Mofo
        // </summary>
        [HttpDelete("{id}", Name = "DeleteMofo")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteMofo(int id)
        {
            try
            {
                await _service.DeleteMofo(id);
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
        }

        // POST api/mofos/{id}/interact
        // <summary>
        // Interact with a Mofo
        // </summary>
        [HttpPost("{id}/interact", Name = "InteractMofo")]
        [ProducesResponseType(typeof(MofoCommand), 201)]
        public async Task<ActionResult<MofoCommand>> InteractMofo(int id, [FromBody] string command)
        {
            try
            {
                LemonSqueezyUser user = await _service.GetCurrentUser(this.HttpContext.User);
                MofoCommand mofoCommand = await _service.InteractMofo(id, user.Id, command);
                return CreatedAtRoute("GetMofoCommand", new { id = mofoCommand.Id }, mofoCommand);
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

        // GET api/mofos/{id}/compileexecutor
        // <summary>
        // Compile an ImplantTemplate for a given Mofo
        // </summary>
        [HttpGet("{id}/compileexecutor", Name = "CompileMofoExecutor")]
        public async Task<ActionResult<byte[]>> CompileMofoExecutor(int id)
        {
            try
            {
                return await _service.CompileMofoExecutorCode(id, Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, false);
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
    }
}
