using Application.DTOs.User;
using Application.Services.User;
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
        public AuthUserController(IUserService userService)
        {
            _userService = userService;
        }
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { Message = "Invalid login data.", Errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });

            var result = await _userService.LoginAsync(loginDto);

            if (!result.Success)
                return Unauthorized(new { Message = result.Error });

            return Ok(new
            {
                Token = result.Value,
                Message = "Login successful."
            });
        }
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage);

                return BadRequest(new
                {
                    Success = false,
                    Message = "Invalid registration data.",
                    Errors = errors
                });
            }

            var result = await _userService.RegisterAsync(registerDto);

            if (!result.Success)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "Registration failed."
                });
            }

            return Ok(new
            {
                Success = true,
                Message = "User registered successfully."
            });
        }
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout(LogoutDto logoutDto)
        {
            if(logoutDto == null || string.IsNullOrWhiteSpace(logoutDto.UserId) || string.IsNullOrWhiteSpace(logoutDto.RefreshToken))
                return BadRequest(new { Message = "UserId and RefreshToken are required." });

            var result =await _userService.LogoutAsync(logoutDto.UserId,logoutDto.RefreshToken);


            if (!result.Success)
                return BadRequest(new {
                    Success = false,
                    Message = result.Error ?? "Logout failed." });
          return Ok(new {
              Success = true,
              Message = "Logout successful." });
        }
        [Authorize]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody]  string RefreshToken)
        {
            if (RefreshToken == null || string.IsNullOrWhiteSpace(RefreshToken))
                return BadRequest(new { Message = "Refresh token is required." });

            var result = await _userService.RefreshTokenAsync(RefreshToken);

            if (!result.Success)
                return Unauthorized(new { Message = result.Error });

            return Ok(new
            {
                Message = "Token refreshed successfully.",
                result.Value
            });
        }
        [Authorize]
        [HttpGet("Profile")]
        public async Task<ActionResult> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("Invalid user.");
            var user = await _userService.GetProfileAsync(userId);
            return Ok(user);
        }
        [Authorize(Roles = "User,Admin")]

        [HttpPost("Update-Profile")]
        public async Task<ActionResult> UpdateUserProfie(UserDto updateUserDto)
        {
            if (updateUserDto == null)
                return BadRequest("Updated Object Should Not To Be Null");
           var result= await _userService.UpdateUserProfileAsync(updateUserDto);

            if (!result.Success)
                return BadRequest(result.Error);

            return Ok(
            new{
                Success=true,
                User= result.Value
            });
        }
        [Authorize(Roles ="User,Admin")]
        [HttpPost("Upload-Image-Profile")]
        public async Task<ActionResult> UploadImageProfile(UploadProfileImageDto uploadProfileImageDto)
        {
            if (uploadProfileImageDto == null)
                return BadRequest("Invalid Image Null");
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
                return Unauthorized("Unauthorized Invalid Token");
            var result=await _userService.UploadUserImageProfile(userId, uploadProfileImageDto);
            if (!result.Success)
                return Unauthorized(result.Error);
            return Ok(new { Success = true, User = result.Value });
        }
        [Authorize]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest dto)
        {
            var result = await _userService.ForgotPasswordAsync(dto.Email);
            if (!result.Success)
                return BadRequest(result.Error);

            return Ok("Password reset link has been sent to your email.");
        }



    }
}
