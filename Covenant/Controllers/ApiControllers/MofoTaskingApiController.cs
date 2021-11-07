// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using LemonSqueezy.Core;
using LemonSqueezy.Models.Mofos;

namespace LemonSqueezy.Controllers
{
    [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
    public class MofoTaskingApiController : Controller
    {
        private readonly ILemonSqueezyService _service;

        public MofoTaskingApiController(ILemonSqueezyService service)
        {
            _service = service;
        }

        // GET: api/taskings
        // <summary>
        // Get MofoTaskings
        // </summary>
        [HttpGet("taskings", Name = "GetAllMofoTaskings")]
        public async Task<ActionResult<IEnumerable<MofoTasking>>> GetAllMofoTaskings()
        {
            return Ok(await _service.GetMofoTaskings());
        }

        // GET: api/mofos/{id}/taskings
        // <summary>
        // Get MofoTaskings for Mofo
        // </summary>
        [HttpGet("mofos/{id}/taskings", Name = "GetMofoTaskings")]
        public async Task<ActionResult<IEnumerable<MofoTasking>>> GetMofoTaskings(int id)
        {
            return Ok(await _service.GetMofoTaskingsForMofo(id));
        }

        // GET: api/mofos/{id}/taskings/search
        // <summary>
        // Get MofoTaskings for Mofo or any child Mofo
        // </summary>
        [HttpGet("mofos/{id}/taskings/search", Name = "GetSearchMofoTaskings")]
        public async Task<ActionResult<IEnumerable<MofoTasking>>> GetSearchMofoTaskings(int id)
        {
            return Ok(await _service.GetMofoTaskingsSearch(id));
        }

        // GET: api/mofos/{id}/taskings/uninitialized
        // <summary>
        // Get uninitialized MofoTaskings for Mofo
        // </summary>
        [HttpGet("mofos/{id}/taskings/uninitialized", Name = "GetUninitializedMofoTaskings")]
        public async Task<ActionResult<IEnumerable<MofoTasking>>> GetUninitializedMofoTaskings(int id)
        {
            return Ok(await _service.GetUninitializedMofoTaskingsForMofo(id));
        }

        // GET: api/mofos/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized MofoTaskings for Mofo or any child Mofo
        // </summary>
        [HttpGet("mofos/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedMofoTaskings")]
        public async Task<ActionResult<IEnumerable<MofoTasking>>> GetSearchUninitializedMofoTaskings(int id)
        {
            IEnumerable<MofoTasking> taskings = await _service.GetMofoTaskingsSearch(id);
            return Ok(taskings
                .Where(GT => GT.Status == MofoTaskingStatus.Uninitialized)
                .ToList());
        }

        // GET api/taskings/{tid}
        // <summary>
        // Get a MofoTasking
        // </summary>
        [HttpGet("taskings/{tid:int}", Name = "GetMofoTasking")]
        public async Task<ActionResult<MofoTasking>> GetMofoTasking(int tid)
        {
            try
            {
                return await _service.GetMofoTasking(tid);
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

        // GET api/taskings/{taskingname}
        // <summary>
        // Get a MofoTasking
        // </summary>
        [HttpGet("mofos/taskings/{taskingname}", Name = "GetMofoTaskingByName")]
        public async Task<ActionResult<MofoTasking>> GetMofoTaskingByName(string taskingname)
        {
            try
            {
                return await _service.GetMofoTaskingByName(taskingname);
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

        // POST api/taskings
        // <summary>
        // Create a MofoTasking
        // </summary>
        [HttpPost("taskings", Name = "CreateMofoTasking")]
        [ProducesResponseType(typeof(MofoTasking), 201)]
        public async Task<ActionResult<MofoTasking>> CreateMofoTasking([FromBody] MofoTasking mofoTasking)
        {
            try
            {
                MofoTasking tasking = await _service.CreateMofoTasking(mofoTasking);
                return CreatedAtRoute(nameof(GetMofoTasking), new { tid = tasking.Id }, tasking);
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

        // PUT api/taskings
        // <summary>
        // Edit a MofoTasking
        // </summary>
        [HttpPut("taskings", Name = "EditMofoTasking")]
        public async Task<ActionResult<MofoTasking>> EditMofoTasking([FromBody] MofoTasking mofoTasking)
        {
            try
            {
                return await _service.EditMofoTasking(mofoTasking);
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

        // DELETE api/taskings/{tid}
        // <summary>
        // Delete a MofoTasking
        // </summary>
        [HttpDelete("taskings/{tid}", Name = "DeleteMofoTasking")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteMofoTasking(int tid)
        {
            try
            {
                await _service.DeleteMofoTasking(tid);
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
