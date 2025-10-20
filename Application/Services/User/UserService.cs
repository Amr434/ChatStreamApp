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
using Microsoft.AspNetCore.Identity;

namespace Application.Services.User
{
    public class UserService : IUserService
    {
        private readonly IUnitOfWork _unitOfWork;

        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;


        public UserService(IUnitOfWork unitOfWork, IMapper mapper, IConfiguration configuration, IEmailService emailService)
        {
            _mapper = mapper;
            _configuration = configuration;
            _unitOfWork = unitOfWork;
            _emailService = emailService;
        }

        public async Task<Result<bool>> ExistsAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<bool>.Failure("User ID cannot be null or empty.");
            try
            {
                var exists = await _unitOfWork.Users.ExistsAsync(userId);

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
                var users = await _unitOfWork.Users.GetAllAsync();
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

                var lastSeen = await _unitOfWork.Users.GetLastSeenAsync(userId);

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
                var onlineUsers = await _unitOfWork.Users.GetOnlineUsersAsync();

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
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);
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
                var user = await _unitOfWork.Users.GetAsync(u => u.Email == loginDto.Email);
                if (user == null)
                    return Result<object>.Failure("Invalid email or password.");
                var isLocked = await _unitOfWork.Users.IsLockedOutAsync(user);
                if (isLocked)
                    return Result<object>.Failure("User account is locked. Please try again later.");

                var isPasswordValid = await _unitOfWork.Users.CheckPasswordAsync(user, loginDto.Password);
                if (!isPasswordValid)
                    return Result<object>.Failure("Invalid email or password.");

                // Generate JWT Access Token
                var accessToken = await _GenerateJwtToken(user);
                if (string.IsNullOrEmpty(accessToken))
                    return Result<object>.Failure("Failed to generate access token.");

                // Delete old refresh tokens (optional but recommended)
                await _unitOfWork.Token.DeleteUserRefreshTokensAsync(user.Id.ToString());

                // Generate new Refresh Token
                var refreshToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Token = GenerateSecureToken(),
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow,
                };

                await _unitOfWork.Token.SaveRefreshTokenAsync(refreshToken);

                await _unitOfWork.Users.SetStatusAsync(user.Id.ToString(), UserStatus.Online);

                await _unitOfWork.SaveChangesAsync();
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
                if (!_unitOfWork.Users.ValidateEmailFormat(registerDto.Email))
                    return Result.Failure("Invalid email format.");


                var existingUser = await _unitOfWork.Users.GetAsync(u => u.Email == registerDto.Email);
                if (existingUser != null)
                    return Result.Failure("Email is already registered.");

                var user = _mapper.Map<ApplicationUser>(registerDto);
                if (user == null)
                    return Result.Failure("Failed to map registration data to user entity.");

                user.Status = UserStatus.Offline;
                user.CreatedAt = DateTime.UtcNow;

                var result = await _unitOfWork.Users.CreateAsync(user, registerDto.Password);
                if (!result.Succeeded)
                    return Result.Failure($"Failed To Create The user Ex:{string.Join("",result.Errors.Select(x=>x.Description))}");

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
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user == null)
                    return Result.Failure($"User with ID '{userId}' does not exist.");

                var updated = await _unitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);
                if (!updated)
                    return Result.Failure("Failed to update user status to Offline.");

                user.LastSeen = DateTimeOffset.UtcNow;
                await _unitOfWork.Users.UpdateAsync(user);

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
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user == null)
                    return Result.Failure($"User with ID '{userId}' does not exist.");

                var updated = await _unitOfWork.Users.SetStatusAsync(userId, status);
                if (!updated)
                    return Result.Failure("Failed to update user status to Offline.");

                user.LastSeen = DateTimeOffset.UtcNow;
                await _unitOfWork.Users.UpdateAsync(user);

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
                var storedToken = await _unitOfWork.Token.GetByTokenAsync(refreshToken);

                if (storedToken == null || storedToken.isRevoked)
                    return Result<bool>.Failure("Invalid or already revoked refresh token.");

                if (storedToken.UserId.ToString() != userId)
                    return Result<bool>.Failure("Refresh token does not belong to this user.");

                storedToken.isRevoked = true;

                await _unitOfWork.Token.UpdateRefreshToken(storedToken);
                await _unitOfWork.Token.SaveChangesAsync();

                await _unitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);

                await _unitOfWork.Users.LogoutAsync();
                return Result<bool>.SuccessResult(true);
            }
            catch (Exception ex)
            {
                return Result<bool>.Failure($"An error occurred during logout: {ex.Message}");
            }
        }

        private async Task<string> _GenerateJwtToken(ApplicationUser user)
        {
            string _secretKey = _configuration["JwtSettings:Key"];
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, user.Email),
            };

            // Add Roles T Use If Have
            var roles = await _unitOfWork.Users.GetUserRolesAsync(user);
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
        private string GenerateSecureToken(int length = 64)
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
                var existingToken = await _unitOfWork.Token.GetByTokenAsync(refreshToken);
                if (existingToken is null)
                    return Result<object>.Failure("Invalid refresh token.");

                if (existingToken.ExpiresAt <= DateTime.UtcNow || existingToken.isRevoked)
                    return Result<object>.Failure("Refresh token is expired or has been revoked.");

                var user = await _unitOfWork.Users.GetAsync(u => u.Id == existingToken.UserId);
                if (user is null)
                    return Result<object>.Failure("User not found for this token.");

                existingToken.isRevoked = true;
                await _unitOfWork.Token.UpdateRefreshToken(existingToken);
                await _unitOfWork.Token.SaveChangesAsync();

                var newRefreshToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Token = GenerateSecureToken(),
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    isRevoked = false
                };

                await _unitOfWork.Token.SaveRefreshTokenAsync(newRefreshToken);

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
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
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

        public async Task<Result<UserDto>> UpdateUserProfileAsync(UserDto updateUserDto,string userId)
        {
            if (updateUserDto == null)
                return Result<UserDto>.Failure("User update object cannot be null.");

            var user = await _unitOfWork.Users.GetAsync(
                u => u.Id.ToString() == userId);
            
            if (user == null)
                return Result<UserDto>.Failure("User not found.");

            var isValidEmailFormate = _unitOfWork.Users.ValidateEmailFormat(updateUserDto.Email);
            if (!isValidEmailFormate)
                return Result<UserDto>.Failure("Email Formate Not Valid");

            _mapper.Map(updateUserDto, user);

            user.LastSeen = DateTime.UtcNow;

            var updateResult = await _unitOfWork.Users.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return Result<UserDto>.Failure(
                    $"Failed to update user profile. Errors: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");

            await _unitOfWork.SaveChangesAsync();

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
                await _unitOfWork.Users.UpdateAsync(user);
                await _unitOfWork.SaveChangesAsync();

                var userDto = _mapper.Map<UserDto>(user);
                return Result<UserDto>.SuccessResult(userDto);
            }
            catch
            {
                return Result<UserDto>.Failure("An Error occured While UploadUserImageProfile");
            }

        }
        public async Task<Result> ForgotPasswordAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return Result.Failure("Email is required.");

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user == null)
                    return Result.Failure("No account found with this email.");

                var token = await _unitOfWork.Users.GeneratePasswordResetTokenAsync(user);
                if (string.IsNullOrWhiteSpace(token))
                    return Result.Failure("Failed to generate reset token.");

                var encodedToken = Uri.EscapeDataString(token);
                var encodedEmail = Uri.EscapeDataString(email);

                var resetLink = $"{_configuration["ClientUrl"]}AuthUser/reset-password?email={encodedEmail}&token={encodedToken}";

                var subject = "Reset Your Password";
                var body = $@"
                    <h3>Password Reset Request</h3>
                    <p>Hello {user.UserName},</p>
                    <p>Click the link below to reset your password. This link will expire soon:</p>
                    <p><a href='{resetLink}'>Reset Password</a></p>
                    <p>If you didn’t request this, please ignore this email.</p>";

                await _emailService.SendEmailAsync(email, subject, body);

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while processing forgot password. Details: {ex.Message}");
            }
        }
        public async Task<Result<string>> ResetPasswordAsync(string email, string token, string newPassword)
        {
            if (string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(token) ||
                string.IsNullOrWhiteSpace(newPassword))
            {
                return Result<string>.Failure("Email, token, and new password are required.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user == null)
                    return Result<string>.Failure("User not found.");

                var decodedToken = Uri.UnescapeDataString(token);

                var resetResult = await _unitOfWork.Users.ResetPasswordAsync(user, decodedToken, newPassword);
                if (!resetResult.Succeeded)
                {
                    var errors = string.Join("; ", resetResult.Errors.Select(e => e.Description));
                    return Result<string>.Failure($"Password reset failed: {errors}");
                }

                var stampResult = await _unitOfWork.Users.UpdateSecurityStampAsync(user);
                if (!stampResult.Succeeded)
                    return Result<string>.Failure("Failed to update security stamp.");

                return Result<string>.SuccessResult("Password has been reset successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"Unexpected error occurred: {ex.Message}");
            }
        }
        public async Task<Result> DeleteUserAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return Result.Failure("Email cannot be null or empty.");

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user is null)
                    return Result.Failure("User not found.");

                var isDeleted = await _unitOfWork.Users.DeleteAsync(user.Id.ToString());
                if (!isDeleted)
                    return Result.Failure("Failed to delete user.");

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure("An unexpected error occurred while deleting the user.");
            }
        }

        public async Task<Result<string>> LockUserAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<string>.Failure("Invalid user ID.");

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user is null)
                    return Result<string>.Failure("User not found.");

                _unitOfWork.Users.LockUser(user);
                var changes = await _unitOfWork.SaveChangesAsync();

                if (changes == 0)
                    return Result<string>.Failure("No changes were applied while locking the user.");

                return Result<string>.SuccessResult("User has been locked successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An unexpected error occurred while locking the user: {ex.Message}");
            }
        }
        public async Task<Result<string>> UnLockUserAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<string>.Failure("Invalid user ID.");

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user is null)
                    return Result<string>.Failure("User not found.");

                _unitOfWork.Users.UnLockUser(user);
                var changes = await _unitOfWork.SaveChangesAsync();

                if (changes == 0)
                    return Result<string>.Failure("No changes were applied while Unlocking the user.");

                return Result<string>.SuccessResult("User has been Unlocked successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An unexpected error occurred while locking the user: {ex.Message}");
            }
        }

     
        public async Task<Result<AdminUpdateUserDto>> UpdateUserProfileAsync(AdminUpdateUserDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Id))
                return Result<AdminUpdateUserDto>.Failure("Invalid request. User ID is required.");

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == dto.Id);
                if (user == null)
                    return Result<AdminUpdateUserDto>.Failure("User not found.");

                if (!string.IsNullOrWhiteSpace(dto.Email) && dto.Email != user.Email)
                {
                    var existingUserByEmail = await _unitOfWork.Users.GetAsync(u => u.Email == dto.Email);
                    if (existingUserByEmail != null)
                        return Result<AdminUpdateUserDto    >.Failure("Email is already taken.");
                }

                if (!string.IsNullOrWhiteSpace(dto.UserName) && dto.UserName != user.UserName)
                {
                    var existingUserByUsername = await _unitOfWork.Users.GetAsync(u => u.UserName == dto.UserName);
                    if (existingUserByUsername != null)
                        return Result<AdminUpdateUserDto>.Failure("Username is already taken.");
                }

                _mapper.Map(dto, user);

                if (dto.Roles != null && dto.Roles.Any())
                {
                    var currentRoles = await _unitOfWork.Users.GetUserRolesAsync(user);
                    var rolesToAdd = dto.Roles.Except(currentRoles);
                    var rolesToRemove = currentRoles.Except(dto.Roles);

                    foreach (var role in rolesToAdd)
                        await _unitOfWork.Users.AddToRoleAsync(user, role);

                    foreach (var role in rolesToRemove)
                        await _unitOfWork.Users.RemoveFromRoleAsync(user, role);
                }

                if (dto.Status.HasValue)
                    user.Status = dto.Status.Value;

                await _unitOfWork.Users.UpdateSecurityStampAsync(user);

                await _unitOfWork.SaveChangesAsync();

                var updateduser = _mapper.Map<AdminUpdateUserDto>(user);
                return Result<AdminUpdateUserDto>.SuccessResult(updateduser);
            }
            catch (Exception ex)
            {
                return Result<AdminUpdateUserDto>.Failure($"An unexpected error occurred while updating user: {ex.Message}");
            }
        }

        public async Task<Result<string>> CreateUserAsync(CreateUserByAdminDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
                return Result<string>.Failure("Email or Password cannot be empty.");

            try
            {
                var isUserExist = await _unitOfWork.Users.ExistsAsync(x => x.Email == dto.Email);
                if (isUserExist)
                    return Result<string>.Failure("User already exists.");

                var user = _mapper.Map<ApplicationUser>(dto);

                if (dto.ProfileImage is not null && dto.ProfileImage.Length > 0)
                {
                    string uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "profile_images");
                    if (!Directory.Exists(uploadsFolder))
                        Directory.CreateDirectory(uploadsFolder);

                    var uniqueFileName = $"{Guid.NewGuid()}_{Path.GetFileName(dto.ProfileImage.FileName)}";
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                        await dto.ProfileImage.CopyToAsync(stream);

                    user.ProfileImageUrl = $"/uploads/profile_images/{uniqueFileName}";
                }

                var result = await _unitOfWork.Users.CreateAsync(user, dto.Password);
                if (!result.Succeeded)
                    return Result<string>.Failure(string.Join(",", result.Errors.Select(e => e.Description)));

                if (dto.Roles != null && dto.Roles.Any())
                    await _unitOfWork.Users.AddToRolesAsync(user, dto.Roles);

                int changeResult = await _unitOfWork.SaveChangesAsync();
                if (changeResult == 0)
                    return Result<string>.Failure("Failed to save changes.");

                return Result<string>.SuccessResult("User result successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An error occurred while creating the user. Details: {ex.Message}");
            }
        }

        public async Task<Result<List<string>>> GetAllRolesAsync()
        {
            try
            {
                var roles = await _unitOfWork.Users.GetAllRolesNameAsync();

                if (roles == null || !roles.Any())
                    return Result<List<string>>.Failure("No roles found.");

                return Result<List<string>>.SuccessResult(roles.ToList());
            }
            catch (Exception ex)
            {
                return Result<List<string>>.Failure($"An error occurred while retrieving roles. Details: {ex.Message}");
            }
        }
        public async Task<Result<string>> RemoveRoleAsync(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return Result<string>.Failure("Role name cannot be null or empty.");

            try
            {
                var role = await _unitOfWork.Users.GetRoleAsync(r =>
                    r.Name.ToLower()== roleName.ToLower());

                if (role is null)
                    return Result<string>.Failure($"Role '{roleName}' not found.");

                var result = await _unitOfWork.Users.DeleteAsync(role);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return Result<string>.Failure($"Failed to remove role. Errors: {errors}");
                }

                await _unitOfWork.SaveChangesAsync();

                return Result<string>.SuccessResult($"Role '{roleName}' removed successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An error occurred while removing the role. Details: {ex.Message}");
            }
        }

        
    }
}

