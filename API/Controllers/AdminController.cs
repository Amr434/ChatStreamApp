using Application.Common.Model;
using Application.DTOs.User;
using Application.Services.User;
using ChatApp.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles ="Admin")]
    public class AdminController : ControllerBase
    {
        private readonly IUserService _userService;
        public AdminController(IUserService userService) 
        {
            _userService= userService;
        }

        [HttpGet("get-all-users")]
        public async Task<IActionResult> GetAllUsers() 
        {
             var results= await  _userService.GetAllUsersAsync();
            if(!results.Success)
                return BadRequest(results.Error);
            return Ok(results);
        }      
        [HttpGet("get-online-users")]
        public async Task<IActionResult> GetOnlineUsers() 
        {
             var results= await  _userService.GetOnlineUsersAsync();
            if(!results.Success)
                return BadRequest(results.Error);
            return Ok(results);
        }
        [HttpGet("get-user-by-id")]
        public async Task<IActionResult> GetUserById(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                return BadRequest("User Id Is Null");
            var result=await _userService.GetUserByIdAsync(userId);
            if(!result.Success)
                return BadRequest($"{result.Error}");

            return Ok(new
            {
                User=result.Value
            });
        }
        [HttpDelete("{email}")]
        public async Task<IActionResult> DeleteUser([FromRoute] string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return BadRequest(new { message = "Email cannot be null or empty." });

            var result = await _userService.DeleteUserAsync(email);

            if (!result.Success)
                return NotFound(new { message = result.Error });

            return Ok(new { message = "User deleted successfully." });
        }
        [HttpPut("lock/{id}")]
        public async Task<IActionResult> LockUser(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                return BadRequest(new { message = "User ID cannot be null or empty." });

            var result = await _userService.LockUserAsync(id);

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            return Ok(new { message = result.Value });
        }

        [HttpPut("unlock/{Id}")]
        public async Task<ActionResult> UnLockUser(string Id)
        {
            if (string.IsNullOrEmpty(Id))
                return BadRequest(new { message = "id cannot be null or empty." });

            var result = await _userService.UnLockUserAsync(Id);
            if(!result.Success)
                return BadRequest(result.Error);
            return Ok(result.Value);

        }
        [HttpPost("update-user-profile")]
        public async Task<ActionResult> UpdateUserProfie(AdminUpdateUserDto updateUserDto)
        {
            if (updateUserDto == null)
                return BadRequest("Updated Object Should Not To Be Null");


            if (string.IsNullOrEmpty(updateUserDto.Id))
                return Unauthorized("User Is Not Authorized");

            var result = await _userService.UpdateUserProfileAsync(updateUserDto);

            if (!result.Success)
                return BadRequest(result.Error);

            return Ok(
            new
            {
                Success = true,
                User = result.Value
            });
        }

        [HttpPost("create-user")]
        public async Task<ActionResult> CreateUser(CreateUserByAdminDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
                return  BadRequest(new { message = "Email or Password cannot be empty." });
           var result=await _userService.CreateUserAsync(dto);
            if (!result.Success)
                return BadRequest(new {Error = result.Error});
            return Ok(new { Message = result.Value });
        }
        [HttpGet("get-all-roles")]
        public async Task<ActionResult> GetALLRoles()
        {
           var result=await _userService.GetAllRolesAsync();
            if (!result.Success)
                return BadRequest(new {Message=result.Value});
            return Ok(new {
                Success=true,
                Roles= result.Value
            });
        }
        [HttpDelete("remove-role{role}")]
        public async Task<ActionResult> RemoveRole(string role)
        {
            if (string.IsNullOrEmpty(role))
                return BadRequest("Role is null or empty");
                
          var result = await _userService.RemoveRoleAsync(role);
            if (!result.Success)
              return BadRequest(new {Message=result.Error});
            return Ok(new {Message="Role is Removed Successfully"});
        }
    }
}
