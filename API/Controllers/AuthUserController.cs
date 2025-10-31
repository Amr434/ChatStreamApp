using Application.DTOs.User;
using Application.Services.User;
using ChatApp.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthUserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<AuthUserController> _logger;

        public AuthUserController(IUserService userService, ILogger<AuthUserController> logger)
        {
            _userService = userService;
            _logger = logger;
        }
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            _logger.LogInformation("Login attempt started for user: {Email}", loginDto.Email);

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();

                _logger.LogWarning("Login failed - invalid model state for user: {Email}. Errors: {@Errors}", loginDto.Email, errors);

                return BadRequest(new
                {
                    Message = "Invalid login data.",
                    Errors = errors
                });
            }

            try
            {
                var result = await _userService.LoginAsync(loginDto);

                if (!result.Success)
                {
                    _logger.LogWarning("Login failed for user: {Email}. Reason: {Error}", loginDto.Email, result.Error);
                    return Unauthorized(new { Message = result.Error });
                }

                _logger.LogInformation("User {Email} logged in successfully.", loginDto.Email);

                return Ok(new
                {
                    Token = result.Value,
                    Message = "Login successful."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred during login for user: {Email}", loginDto.Email);
                return StatusCode(500, new { Message = "An unexpected error occurred during login." });
            }
        }
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            _logger.LogInformation("[AuthUserController] Register endpoint called for email: {Email}", registerDto?.Email);

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                _logger.LogWarning("[AuthUserController] Invalid registration data for email: {Email}. Errors: {Errors}", registerDto?.Email, string.Join(", ", errors));

                return BadRequest(new
                {
                    Success = false,
                    Message = "Invalid registration data.",
                    Errors = errors
                });
            }

            try
            {
                _logger.LogInformation("[AuthUserController] Attempting to register new user with email: {Email}", registerDto.Email);

                var result = await _userService.RegisterAsync(registerDto);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] Registration failed for email: {Email}. Reason: {Reason}", registerDto.Email, result.Error ?? "Unknown error");

                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Registration failed."
                    });
                }

                _logger.LogInformation("[AuthUserController] User registered successfully: {Email}", registerDto.Email);

                return Ok(new
                {
                    Success = true,
                    Message = "User registered successfully."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error occurred during registration for email: {Email}", registerDto?.Email);

                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred during registration."
                });
            }
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto logoutDto)
        {
            _logger.LogInformation("[AuthUserController] Logout endpoint called for UserId: {UserId}", logoutDto?.UserId);

            if (logoutDto == null || string.IsNullOrWhiteSpace(logoutDto.UserId) || string.IsNullOrWhiteSpace(logoutDto.RefreshToken))
            {
                _logger.LogWarning("[AuthUserController] Invalid logout request. Missing UserId or RefreshToken.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "UserId and RefreshToken are required."
                });
            }

            try
            {
                _logger.LogInformation("[AuthUserController] Attempting to logout user: {UserId}", logoutDto.UserId);

                var result = await _userService.LogoutAsync(logoutDto.UserId, logoutDto.RefreshToken);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] Logout failed for UserId: {UserId}. Reason: {Reason}", logoutDto.UserId, result.Error ?? "Unknown error");

                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Logout failed."
                    });
                }

                _logger.LogInformation("[AuthUserController] Logout successful for UserId: {UserId}", logoutDto.UserId);

                return Ok(new
                {
                    Success = true,
                    Message = "Logout successful."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error during logout for UserId: {UserId}", logoutDto?.UserId);

                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred during logout."
                });
            }
        }
        [Authorize]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
        {
            _logger.LogInformation("[AuthUserController] RefreshToken endpoint called.");

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                _logger.LogWarning("[AuthUserController] RefreshToken failed: Missing refresh token in request.");
                return BadRequest(new
                {
                    Success = false,
                    Message = "Refresh token is required."
                });
            }

            try
            {
                _logger.LogInformation("[AuthUserController] Attempting to refresh token.");

                var result = await _userService.RefreshTokenAsync(refreshToken);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] RefreshToken failed. Reason: {Reason}", result.Error ?? "Unknown error.");
                    return Unauthorized(new
                    {
                        Success = false,
                        Message = result.Error ?? "Unauthorized request."
                    });
                }

                _logger.LogInformation("[AuthUserController] Token refreshed successfully.");

                return Ok(new
                {
                    Success = true,
                    Message = "Token refreshed successfully.",
                    result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error during token refresh.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while refreshing the token."
                });
            }
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<ActionResult> GetProfile()
        {
            _logger.LogInformation("[AuthUserController] GetProfile endpoint called.");

            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("[AuthUserController] GetProfile failed: Missing or invalid user ID in token.");
                    return Unauthorized(new
                    {
                        Success = false,
                        Message = "Invalid or missing user ID."
                    });
                }

                _logger.LogInformation("[AuthUserController] Retrieving profile for user ID: {UserId}", userId);

                var result = await _userService.GetProfileAsync(userId);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] GetProfile failed for user ID {UserId}. Reason: {Reason}", userId, result.Error);
                    return NotFound(new
                    {
                        Success = false,
                        Message = result.Error ?? "User profile not found."
                    });
                }

                _logger.LogInformation("[AuthUserController] Successfully retrieved profile for user ID: {UserId}", userId);

                return Ok(new
                {
                    Success = true,
                    Message = "Profile retrieved successfully.",
                    Data = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error while retrieving user profile.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while retrieving the profile."
                });
            }
        }

        [Authorize(Roles = "User,Admin")]
        [HttpPut("update-profile")]
        public async Task<ActionResult> UpdateProfie([FromBody] UserDto updateUserDto)
        {
            _logger.LogInformation("[AuthUserController] UpdateProfile endpoint called.");

            try
            {
                if (updateUserDto == null)
                {
                    _logger.LogWarning("[AuthUserController] UpdateProfile failed: Request body is null.");
                    return BadRequest(new
                    {
                        Success = false,
                        Message = "Updated object should not be null."
                    });
                }

                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("[AuthUserController] UpdateProfile failed: Missing or invalid user ID from claims.");
                    return Unauthorized(new
                    {
                        Success = false,
                        Message = "User is not authorized."
                    });
                }

                _logger.LogInformation("[AuthUserController] Attempting to update profile for user ID: {UserId}", userId);

                var result = await _userService.UpdateUserProfileAsync(updateUserDto, userId);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] UpdateProfile failed for user ID {UserId}. Reason: {Error}", userId, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to update profile."
                    });
                }

                _logger.LogInformation("[AuthUserController] Profile updated successfully for user ID: {UserId}", userId);

                return Ok(new
                {
                    Success = true,
                    Message = "Profile updated successfully.",
                    User = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error while updating user profile.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while updating the profile."
                });
            }
        }

        [Authorize(Roles ="User,Admin")]
        [HttpPost("upload-profile-image")]
        public async Task<ActionResult> UploadImageProfile([FromBody] UploadProfileImageDto uploadProfileImageDto)
        {
            _logger.LogInformation("[AuthUserController] UploadImageProfile endpoint called.");

            try
            {
                if (uploadProfileImageDto == null)
                {
                    _logger.LogWarning("[AuthUserController] UploadImageProfile failed: UploadProfileImageDto is null.");
                    return BadRequest(new
                    {
                        Success = false,
                        Message = "Invalid image data. Request body cannot be null."
                    });
                }

                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("[AuthUserController] UploadImageProfile failed: Missing or invalid user ID from claims.");
                    return Unauthorized(new
                    {
                        Success = false,
                        Message = "Unauthorized. Invalid or missing token."
                    });
                }

                _logger.LogInformation("[AuthUserController] Attempting to upload profile image for user ID: {UserId}", userId);

                var result = await _userService.UploadUserImageProfile(userId, uploadProfileImageDto);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] UploadImageProfile failed for user ID {UserId}. Reason: {Error}", userId, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to upload profile image."
                    });
                }

                _logger.LogInformation("[AuthUserController] Profile image uploaded successfully for user ID: {UserId}", userId);

                return Ok(new
                {
                    Success = true,
                    Message = "Profile image uploaded successfully.",
                    User = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error occurred while uploading profile image.");
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while uploading the profile image."
                });
            }
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest dto)
        {
            _logger.LogInformation("[AuthUserController] ForgotPassword endpoint called.");

            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                {
                    _logger.LogWarning("[AuthUserController] ForgotPassword failed: Missing or invalid email.");
                    return BadRequest(new
                    {
                        Success = false,
                        Message = "Email is required."
                    });
                }

                _logger.LogInformation("[AuthUserController] Attempting to send password reset email to: {Email}", dto.Email);

                var result = await _userService.ForgotPasswordAsync(dto.Email);

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] ForgotPassword failed for {Email}. Reason: {Error}", dto.Email, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Failed to send password reset email."
                    });
                }

                _logger.LogInformation("[AuthUserController] Password reset link sent successfully to {Email}", dto.Email);

                return Ok(new
                {
                    Success = true,
                    Message = "Password reset link has been sent to your email."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error occurred while processing ForgotPassword for {Email}", dto?.Email);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while processing your password reset request."
                });
            }
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<ActionResult> ResetPassword([FromQuery] ResetPasswordRequest resetPasswordRequest)
        {
            _logger.LogInformation("[AuthUserController] ResetPassword endpoint called.");

            try
            {
                if (resetPasswordRequest is null ||
                    string.IsNullOrEmpty(resetPasswordRequest.NewPassword) ||
                    string.IsNullOrEmpty(resetPasswordRequest.Token) ||
                    string.IsNullOrEmpty(resetPasswordRequest.Email))
                {
                    _logger.LogWarning("[AuthUserController] ResetPassword failed: Missing or invalid data. Request: {@ResetPasswordRequest}", resetPasswordRequest);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = "Invalid ResetPasswordRequest data."
                    });
                }

                _logger.LogInformation("[AuthUserController] Attempting to reset password for email: {Email}", resetPasswordRequest.Email);

                var result = await _userService.ResetPasswordAsync(
                    resetPasswordRequest.Email,
                    resetPasswordRequest.Token,
                    resetPasswordRequest.NewPassword
                );

                if (!result.Success)
                {
                    _logger.LogWarning("[AuthUserController] Password reset failed for {Email}. Reason: {Error}", resetPasswordRequest.Email, result.Error);
                    return BadRequest(new
                    {
                        Success = false,
                        Message = result.Error ?? "Password reset failed."
                    });
                }

                _logger.LogInformation("[AuthUserController] Password reset successfully for {Email}", resetPasswordRequest.Email);

                return Ok(new
                {
                    Success = true,
                    Message = result.Value
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AuthUserController] Unexpected error occurred while resetting password for {Email}", resetPasswordRequest?.Email);
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Success = false,
                    Message = "An unexpected error occurred while resetting the password."
                });
            }
        }

    }
}
