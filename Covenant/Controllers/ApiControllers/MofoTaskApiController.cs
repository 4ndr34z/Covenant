// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using LemonSqueezy.Core;
using LemonSqueezy.Models.Mofos;

namespace LemonSqueezy.Controllers
{
    [ApiController, Route("api/mofotasks"), Authorize(Policy = "RequireJwtBearer")]
    public class MofoTaskApiController : Controller
    {
        private readonly ILemonSqueezyService _service;

        public MofoTaskApiController(ILemonSqueezyService service)
        {
            _service = service;
        }

        // GET: api/mofotasks
        // <summary>
        // Get Tasks
        // </summary>
        [HttpGet(Name = "GetMofoTasks")]
        public async Task<ActionResult<IEnumerable<MofoTask>>> GetMofoTasks()
        {
            return Ok(await _service.GetMofoTasks());
        }

        // GET: api/mofotasks/{id}
        // <summary>
        // Get a Task by Id
        // </summary>
        [HttpGet("{id:int}", Name = "GetMofoTask")]
        public async Task<ActionResult<MofoTask>> GetMofoTask(int id)
        {
            try
            {
                return await _service.GetMofoTask(id);
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

        // POST api/mofotasks
        // <summary>
        // Create a Task
        // </summary>
        [HttpPost(Name = "CreateMofoTask")]
        [ProducesResponseType(typeof(MofoTask), 201)]
        public async Task<ActionResult<MofoTask>> CreateMofoTask([FromBody] MofoTask task)
        {
            MofoTask savedTask = await _service.CreateMofoTask(task);
            return CreatedAtRoute(nameof(GetMofoTask), new { id = savedTask.Id }, savedTask);
        }

        // PUT api/mofotasks
        // <summary>
        // Edit a Task
        // </summary>
        [HttpPut(Name = "EditMofoTask")]
        public async Task<ActionResult<MofoTask>> EditMofoTask([FromBody] MofoTask task)
        {
            try
            {
                return await _service.EditMofoTask(task);
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

        // DELETE api/mofotasks/{id}
        // <summary>
        // Delete a Task
        // </summary>
        [HttpDelete("{id}", Name = "DeleteMofoTask")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteMofoTask(int id)
        {
            try
            {
                await _service.DeleteMofoTask(id);
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
