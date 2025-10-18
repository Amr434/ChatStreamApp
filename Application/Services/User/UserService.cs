using Application.Common.Model;
using Application.DTOs.User;
using AutoMapper;
using ChatApp.Infrastructure.Identity;
using Domain.Enums;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Domain.Entities;
using System.Security.Cryptography;
using AutoMapper.Configuration.Annotations;
using Microsoft.EntityFrameworkCore;
using Application.Interfaces.Repositories;
using Application.Interfaces;
using Microsoft.AspNetCore.Hosting;
using System.Text.Json;
using Application.Settings;

namespace Application.Services.User
{
    public class UserService : IUserService
    {
        private readonly IUnitOfWork _UnitOfWork;

        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;


        public UserService(IUnitOfWork unitOfWork, IMapper mapper, IConfiguration configuration)
        {
            _mapper = mapper;
            _configuration = configuration;
            _UnitOfWork = unitOfWork;
        }

        public async Task<Result<bool>> ExistsAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<bool>.Failure("User ID cannot be null or empty.");
            try
            {
                var exists = await _UnitOfWork.Users.ExistsAsync(userId);

                if (!exists)
                    return Result<bool>.Failure($"User with ID '{userId}' was not found.");

                return Result<bool>.SuccessResult(true);
            }
            catch (Exception ex)
            {
                return Result<bool>.Failure($"An error occurred while checking user existence: {ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ApplicationUser>>> GetAllUsersAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var users = await _UnitOfWork.Users.GetAllAsync();
                if (users == null || !users.Any())
                    return Result<IEnumerable<ApplicationUser>>.Failure("No users found in the system.");

                return Result<IEnumerable<ApplicationUser>>.SuccessResult(users);
            }
            catch (Exception ex)
            {
                return Result<IEnumerable<ApplicationUser>>.Failure($"An error occurred while retrieving users: {ex.Message}");
            }
        }

        public async Task<Result<DateTime?>> GetLastSeenAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<DateTime?>.Failure("User ID cannot be null or empty.");
            try
            {

                var lastSeen = await _UnitOfWork.Users.GetLastSeenAsync(userId);

                if (lastSeen == null)
                    return Result<DateTime?>.Failure($"No last seen record found for user ID '{userId}'.");
                return Result<DateTime?>.SuccessResult(lastSeen);
            }
            catch (Exception ex)
            {
                return Result<DateTime?>.Failure($"An error occurred while retrieving the last seen time: {ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ApplicationUser>>> GetOnlineUsersAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var onlineUsers = await _UnitOfWork.Users.GetOnlineUsersAsync();

                if (onlineUsers == null || !onlineUsers.Any())
                    return Result<IEnumerable<ApplicationUser>>.Failure("No online users found.");

                return Result<IEnumerable<ApplicationUser>>.SuccessResult(onlineUsers);
            }
            catch (Exception ex)
            {
                return Result<IEnumerable<ApplicationUser>>.Failure($"An error occurred while retrieving online users: {ex.Message}");
            }
        }

        public async Task<Result<ApplicationUser>> GetUserByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<ApplicationUser>.Failure("User ID cannot be null or empty.");
            try
            {
                var user = await _UnitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);
                if (user == null)
                    return Result<ApplicationUser>.Failure("User  cannot be Found.");
                return Result<ApplicationUser>.SuccessResult(user);

            }
            catch (Exception ex)
            {
                return Result<ApplicationUser>.Failure($"Ann Error Accured While Attempting To Get The User error {ex.Message}");
            }
        }

        public async Task<Result<object>> LoginAsync(LoginDto loginDto)
        {
            if (loginDto == null)
                return Result<object>.Failure("Login data cannot be null.");

            if (string.IsNullOrWhiteSpace(loginDto.Email) || string.IsNullOrWhiteSpace(loginDto.Password))
                return Result<object>.Failure("Email and password are required.");

            try
            {
                var user = await _UnitOfWork.Users.GetAsync(u => u.Email == loginDto.Email);
                if (user == null)
                    return Result<object>.Failure("Invalid email or password.");

                var isPasswordValid = await _UnitOfWork.Users.CheckPasswordAsync(user, loginDto.Password);
                if (!isPasswordValid)
                    return Result<object>.Failure("Invalid email or password.");

                // Generate JWT Access Token
                var accessToken =await _GenerateJwtToken(user);
                if (string.IsNullOrEmpty(accessToken))
                    return Result<object>.Failure("Failed to generate access token.");

                // Delete old refresh tokens (optional but recommended)
                await _UnitOfWork.Token.DeleteUserRefreshTokensAsync(user.Id.ToString());

                // Generate new Refresh Token
                var refreshToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Token = GenerateSecureToken(),
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow,
                };

                await _UnitOfWork.Token.SaveRefreshTokenAsync(refreshToken);

                await _UnitOfWork.Users.SetStatusAsync(user.Id.ToString(), UserStatus.Online);

                await _UnitOfWork.SaveChangesAsync();
                return Result<object>.SuccessResult(new
                {
                    Success = true,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken.Token
                });
            }
            catch (Exception ex)
            {
                return Result<object>.Failure($"An unexpected error occurred during login: {ex.Message}");
            }
        }
        public async Task<Result> RegisterAsync(RegisterDto registerDto)
        {
            if (registerDto == null)
                return Result.Failure("Registration data cannot be null.");

            if (string.IsNullOrWhiteSpace(registerDto.Email) || string.IsNullOrWhiteSpace(registerDto.Password))
                return Result.Failure("Email and password are required.");

            try
            {
                if (!_UnitOfWork.Users.ValidateEmailFormat(registerDto.Email))
                    return Result.Failure("Invalid email format.");


                var existingUser = await _UnitOfWork.Users.GetAsync(u => u.Email == registerDto.Email);
                if (existingUser != null)
                    return Result.Failure("Email is already registered.");

                var user = _mapper.Map<ApplicationUser>(registerDto);
                if (user == null)
                    return Result.Failure("Failed to map registration data to user entity.");

                user.Status = UserStatus.Offline;
                user.CreatedAt = DateTime.UtcNow;

                var created = await _UnitOfWork.Users.CreateAsync(user, registerDto.Password);
                if (!created)
                    return Result.Failure("Failed to create user. Please try again.");

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An unexpected error occurred during registration: {ex.Message}");
            }
        }


        public async Task<Result> SetUserOfflineAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result.Failure("User ID cannot be null or empty.");

            try
            {
                var user = await _UnitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user == null)
                    return Result.Failure($"User with ID '{userId}' does not exist.");

                var updated = await _UnitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);
                if (!updated)
                    return Result.Failure("Failed to update user status to Offline.");

                user.LastSeen = DateTimeOffset.UtcNow;
                await _UnitOfWork.Users.UpdateAsync(user);

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while setting user Offline: {ex.Message}");
            }
        }

        

        public async Task<Result> SetUserStatusAsync(string userId, UserStatus status)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result.Failure("User ID cannot be null or empty.");

            try
            {
                var user = await _UnitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user == null)
                    return Result.Failure($"User with ID '{userId}' does not exist.");

                var updated = await _UnitOfWork.Users.SetStatusAsync(userId, status);
                if (!updated)
                    return Result.Failure("Failed to update user status to Offline.");

                user.LastSeen = DateTimeOffset.UtcNow;
                await _UnitOfWork.Users.UpdateAsync(user);

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while setting user Offline: {ex.Message}");
            }
        }

        public async Task<Result<bool>> LogoutAsync(string userId, string refreshToken)
        {
            if (string.IsNullOrEmpty(userId))
                return Result<bool>.Failure("User ID cannot be null or empty.");

            if (string.IsNullOrEmpty(refreshToken))
                return Result<bool>.Failure("Refresh token cannot be null or empty.");

            try
            {
                var storedToken = await _UnitOfWork.Token.GetByTokenAsync(refreshToken);

                if (storedToken == null || storedToken.isRevoked)
                    return Result<bool>.Failure("Invalid or already revoked refresh token.");

                if (storedToken.UserId.ToString() != userId)
                    return Result<bool>.Failure("Refresh token does not belong to this user.");

                storedToken.isRevoked = true;

                await _UnitOfWork.Token.UpdateRefreshToken(storedToken);
                await _UnitOfWork.Token.SaveChangesAsync();

                await _UnitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);

                await _UnitOfWork.Users.LogoutAsync();
                return Result<bool>.SuccessResult(true);
            }
            catch (Exception ex)
            {
                return Result<bool>.Failure($"An error occurred during logout: {ex.Message}");
            }
        }

        private async Task<string> _GenerateJwtToken(ApplicationUser user)
        {
            string  _secretKey = _configuration["JwtSettings:Key"];
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, user.Email),
            };

            // Add Roles T Use If Have
           var roles= await _UnitOfWork.Users.GetUserRolesAsync(user);
            if (roles != null || roles.Count == 0)
                claims.AddRange(roles.Select(x => new Claim(ClaimTypes.Role, x)));
            else
                claims.Add(new Claim(ClaimTypes.Role, "User"));
            
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private  string GenerateSecureToken(int length = 64)
        {
            var randomBytes = new byte[length];

            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(randomBytes);

            var token = Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');

            return token;
        }

        public async Task<Result<object>> RefreshTokenAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return Result<object>.Failure("Refresh token cannot be null or empty.");

            try
            {
                var existingToken = await _UnitOfWork.Token.GetByTokenAsync(refreshToken);
                if (existingToken is null)
                    return Result<object>.Failure("Invalid refresh token.");

                if (existingToken.ExpiresAt <= DateTime.UtcNow || existingToken.isRevoked)
                    return Result<object>.Failure("Refresh token is expired or has been revoked.");

                var user = await _UnitOfWork.Users.GetAsync(u => u.Id == existingToken.UserId);
                if (user is null)
                    return Result<object>.Failure("User not found for this token.");

                existingToken.isRevoked = true;
                await _UnitOfWork.Token.UpdateRefreshToken(existingToken);
                await _UnitOfWork.Token.SaveChangesAsync();

                var newRefreshToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Token = GenerateSecureToken(),
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    isRevoked = false
                };

                await _UnitOfWork.Token.SaveRefreshTokenAsync(newRefreshToken);

                var newAccessToken = await _GenerateJwtToken(user);
                if (string.IsNullOrEmpty(newAccessToken))
                    return Result<object>.Failure("Failed to generate access token.");

                return Result<object>.SuccessResult(new
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken.Token
                });
            }
            catch (Exception ex)
            {
                return Result<object>.Failure($"An error occurred while refreshing token: {ex.Message}");
            }
        }

        public async Task<Result<UserDto>> GetProfileAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<UserDto>.Failure("User ID cannot be null or empty.");

            try
            {
                var user = await _UnitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user == null)
                    return Result<UserDto>.Failure("User not found.");

                var userDto = _mapper.Map<UserDto>(user);

                return Result<UserDto>.SuccessResult(userDto);
            }
            catch (Exception ex)
            {
                return Result<UserDto>.Failure($"An error occurred while retrieving the profile: {ex.Message}");
            }
        }

        public async Task<Result<UserDto>> UpdateUserProfileAsync(UserDto updateUserDto)
        {
            if (updateUserDto == null)
                return Result<UserDto>.Failure("User update object cannot be null.");

            var user = await _UnitOfWork.Users.GetAsync(
                u => u.NormalizedEmail.ToString()==updateUserDto.Email.ToUpper());

            if (user == null)
                return Result<UserDto>.Failure("User not found.");

           var isValidEmailFormate= _UnitOfWork.Users.ValidateEmailFormat(updateUserDto.Email);
            if (!isValidEmailFormate)
                return Result<UserDto>.Failure("Email Formate Not Valid");

            _mapper.Map(updateUserDto, user);

            user.LastSeen = DateTime.UtcNow;

            var updateResult = await _UnitOfWork.Users.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return Result<UserDto>.Failure(
                    $"Failed to update user profile. Errors: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");

            await _UnitOfWork.SaveChangesAsync();

            return await GetProfileAsync(user.Id.ToString());
        }

        public async Task<Result<UserDto>> UploadUserImageProfile(string userId, UploadProfileImageDto uploadProfileImageDto)
        {
            if (userId == null || uploadProfileImageDto.Image == null || uploadProfileImageDto.Image.Length == 0)
                return Result<UserDto>.Failure("Invalid Image Upload Request.");
            
                var userResult = await GetUserByIdAsync(userId);
                if (!userResult.Success || userResult.Value == null)
                    return Result<UserDto>.Failure("User not found.");
            var user = userResult.Value;

            try
            {

                string uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "profile_images");
                if (!Directory.Exists(uploadPath))
                    Directory.CreateDirectory(uploadPath);

                var fileName = $"{Guid.NewGuid()}{Path.GetExtension(uploadProfileImageDto.Image.FileName)}";
                var filePath = Path.Combine(uploadPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await uploadProfileImageDto.Image.CopyToAsync(stream);
                }

                user.ProfileImageUrl = $"/uploads/profile_images/{fileName}";
                await _UnitOfWork.Users.UpdateAsync(user);
                await _UnitOfWork.SaveChangesAsync();

                var userDto = _mapper.Map<UserDto>(user);
                return Result<UserDto>.SuccessResult(userDto);
            }
            catch
            {
                return Result<UserDto>.Failure("An Error occured While UploadUserImageProfile");
            }
                
        }
    }
}
