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
        private readonly ILogger<AdminController> _logger;

        public AdminController(IUserService userService,ILogger<AdminController> logger) 
        {
            _userService = userService;
            _logger = logger;
        }

        [HttpGet("get-all-users")]
        public async Task<IActionResult> GetAllUsers()
        {
            _logger.LogInformation("[AdminController] GetAllUsers endpoint called.");

            try
            {
                var results = await _userService.GetAllUsersAsync();

                if (!results.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to retrieve users. Reason: {Error}", results.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = results.Error ?? "Failed to fetch users."
                    });
                }

                _logger.LogInformation("[AdminController] Successfully retrieved {UserCount} users.", results.Value?.Count ?? 0);

                return Ok(new
                {
                    Success = true,
                    Users = results.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error occurred while retrieving all users.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while retrieving users."
                });
            }
        }

        [HttpGet("get-online-users")]
        public async Task<IActionResult> GetOnlineUsers()
        {
            _logger.LogInformation("[AdminController] GetOnlineUsers endpoint called.");

            try
            {
                var results = await _userService.GetOnlineUsersAsync();

                if (!results.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to retrieve online users. Reason: {Error}", results.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = results.Error ?? "Failed to fetch online users."
                    });
                }

                _logger.LogInformation("[AdminController] Successfully retrieved {Count} online users.", results.Value.ToList()?.Count ?? 0);

                return Ok(new
                {
                    Success = true,
                    Users = results.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error occurred while retrieving online users.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while retrieving online users."
                });
            }
        }

        [HttpGet("get-user-by-id")]
        public async Task<IActionResult> GetUserById(string userId)
        {
            _logger.LogInformation("[AdminController] GetUserById called with userId: {UserId}", userId);

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("[AdminController] GetUserById failed - UserId is null or empty.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "User Id cannot be null or empty."
                });
            }

            try
            {
                var result = await _userService.GetUserByIdAsync(userId);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] GetUserById failed for userId: {UserId}. Reason: {Error}", userId, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to retrieve user."
                    });
                }

                _logger.LogInformation("[AdminController] Successfully retrieved user with Id: {UserId}", userId);

                return Ok(new
                {
                    Success = true,
                    User = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error while retrieving user by Id: {UserId}", userId);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while retrieving the user."
                });
            }
        }

        [HttpDelete("delete-user/{email}")]
        public async Task<IActionResult> DeleteUser([FromRoute] string email)
        {
            _logger.LogInformation("[AdminController] DeleteUser called with email: {Email}", email);

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("[AdminController] DeleteUser failed - Email is null or empty.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "Email cannot be null or empty."
                });
            }

            try
            {
                var result = await _userService.DeleteUserAsync(email);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] DeleteUser failed for email: {Email}. Reason: {Error}", email, result.Error);
                    return NotFound(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to delete user."
                    });
                }

                _logger.LogInformation("[AdminController] User deleted successfully. Email: {Email}", email);

                return Ok(new
                {
                    Success = true,
                    Message = "User deleted successfully."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error while deleting user with email: {Email}", email);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while deleting the user."
                });
            }
        }

        [HttpPost("lock-user/{id}")]
        public async Task<IActionResult> LockUser(string id)
        {
            _logger.LogInformation("[AdminController] LockUser called with ID: {UserId}", id);

            if (string.IsNullOrWhiteSpace(id))
            {
                _logger.LogWarning("[AdminController] LockUser failed - User ID is null or empty.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "User ID cannot be null or empty."
                });
            }

            try
            {
                var result = await _userService.LockUserAsync(id);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to lock user with ID: {UserId}. Reason: {Error}", id, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to lock user."
                    });
                }

                _logger.LogInformation("[AdminController] User locked successfully. UserId: {UserId}", id);

                return Ok(new
                {
                    Success = true,
                    Message = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error while locking user with ID: {UserId}", id);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while locking the user."
                });
            }
        }

        [HttpPost("unlock-user/{id}")]
        public async Task<ActionResult> UnLockUser(string id)
        {
            _logger.LogInformation("[AdminController] UnLockUser called with ID: {UserId}", id);

            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("[AdminController] UnLockUser failed - User ID is null or empty.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "User ID cannot be null or empty."
                });
            }

            try
            {
                var result = await _userService.UnLockUserAsync(id);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to unlock user with ID: {UserId}. Reason: {Error}", id, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to unlock user."
                    });
                }

                _logger.LogInformation("[AdminController] User unlocked successfully. UserId: {UserId}", id);

                return Ok(new
                {
                    Success = true,
                    Message = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error while unlocking user with ID: {UserId}", id);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while unlocking the user."
                });
            }
        }

        [HttpPut("update-user-profile")]
        public async Task<ActionResult> UpdateUserProfie(AdminUpdateUserDto updateUserDto)
        {
            _logger.LogInformation("[AdminController] UpdateUserProfie called for User ID: {UserId}", updateUserDto?.Id);

            if (updateUserDto == null)
            {
                _logger.LogWarning("[AdminController] UpdateUserProfie failed - Request body is null.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "Updated object should not be null."
                });
            }

            if (string.IsNullOrEmpty(updateUserDto.Id))
            {
                _logger.LogWarning("[AdminController] UpdateUserProfie failed - User ID is missing or unauthorized.");
                return Unauthorized(new
                {
                    Success = false,
                    Message = "User is not authorized."
                });
            }

            try
            {
                var result = await _userService.UpdateUserProfileAsync(updateUserDto);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to update user profile for ID: {UserId}. Reason: {Error}", updateUserDto.Id, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to update user profile."
                    });
                }

                _logger.LogInformation("[AdminController] User profile updated successfully for ID: {UserId}", updateUserDto.Id);

                return Ok(new
                {
                    Success = true,
                    User = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error while updating user profile for ID: {UserId}", updateUserDto.Id);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while updating the user profile."
                });
            }
        }

        [HttpPost("create-user")]
        public async Task<ActionResult> CreateUser(CreateUserByAdminDto dto)
        {
            _logger.LogInformation("[AdminController] CreateUser called with Email: {Email}", dto?.Email);

            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
            {
                _logger.LogWarning("[AdminController] CreateUser failed - Invalid request data. Email or Password is missing.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "Email or Password cannot be empty."
                });
            }

            try
            {
                var result = await _userService.CreateUserAsync(dto);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to create user with Email: {Email}. Reason: {Error}", dto.Email, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Error = result.Error
                    });
                }

                _logger.LogInformation("[AdminController] User created successfully with Email: {Email}", dto.Email);

                return Ok(new
                {
                    Success = true,
                    Message = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error occurred while creating user with Email: {Email}", dto.Email);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while creating the user."
                });
            }
        }

        [HttpGet("get-all-roles")]
        public async Task<ActionResult> GetALLRoles()
        {
            _logger.LogInformation("[AdminController] GetALLRoles called.");

            try
            {
                var result = await _userService.GetAllRolesAsync();

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to retrieve roles. Reason: {Error}", result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error
                    });
                }

                _logger.LogInformation("[AdminController] Retrieved {Count} roles successfully.", result.Value?.Count() ?? 0);

                return Ok(new
                {
                    Success = true,
                    Roles = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error occurred while retrieving roles.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while retrieving roles."
                });
            }
        }

        [HttpDelete("remove-role{role}")]
        public async Task<ActionResult> RemoveRole(string role)
        {
            _logger.LogInformation("[AdminController] RemoveRole called with role: {Role}", role);

            if (string.IsNullOrEmpty(role))
            {
                _logger.LogWarning("[AdminController] RemoveRole failed — role name is null or empty.");
                return BadRequest(new { Message = "Role is null or empty" });
            }

            try
            {
                var result = await _userService.RemoveRoleAsync(role);

                if (!result.Success)
                {
                    _logger.LogWarning("[AdminController] Failed to remove role '{Role}'. Reason: {Error}", role, result.Error);
                    return BadRequest(new { Message = result.Error });
                }

                _logger.LogInformation("[AdminController] Role '{Role}' removed successfully.", role);
                return Ok(new { Message = "Role removed successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AdminController] Unexpected error occurred while removing role '{Role}'.", role);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Message = "An unexpected error occurred while removing the role."
                });
            }
        }

    }
}
