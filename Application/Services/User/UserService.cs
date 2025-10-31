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
using Microsoft.Extensions.Logging;

namespace Application.Services.User
{
    public class UserService : IUserService
    {
        private readonly IUnitOfWork _unitOfWork;

        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILogger<UserService> _logger;


        public UserService(IUnitOfWork unitOfWork, IMapper mapper, IConfiguration configuration, IEmailService emailService,ILogger<UserService> logger)
        {
            _mapper = mapper;
            _configuration = configuration;
            _unitOfWork = unitOfWork;
            _emailService = emailService;
            _logger = logger;
        }

        public async Task<Result<bool>> ExistsAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("User ID is null or empty.");
                return Result<bool>.Failure("User ID cannot be null or empty.");
            }

            try
            {
                var exists = await _unitOfWork.Users.ExistsAsync(userId);

                if (!exists)
                {
                    _logger.LogWarning("User with ID {UserId} does not exist.", userId);
                    return Result<bool>.Failure($"User with ID '{userId}' was not found.");
                }

                _logger.LogInformation("User with ID {UserId} exists.", userId);
                return Result<bool>.SuccessResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while checking if user {UserId} exists.", userId);
                return Result<bool>.Failure("An unexpected error occurred while checking user existence.");
            }
        }

        public async Task<Result<IEnumerable<ApplicationUser>>> GetAllUsersAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var users = await _unitOfWork.Users.GetAllAsync();

                if (users == null || !users.Any())
                {
                    _logger.LogWarning("No users were found in the system.");
                    return Result<IEnumerable<ApplicationUser>>.Failure("No users found in the system.");
                }

                _logger.LogInformation("Retrieved {UserCount} users successfully.", users.Count());
                return Result<IEnumerable<ApplicationUser>>.SuccessResult(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving users.");
                return Result<IEnumerable<ApplicationUser>>.Failure("An unexpected error occurred while retrieving users.");
            }
        }

        public async Task<Result<DateTime?>> GetLastSeenAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogError("User ID cannot be null or empty.");
                return Result<DateTime?>.Failure("User ID cannot be null or empty.");
            }
            try
            {
                var lastSeen = await _unitOfWork.Users.GetLastSeenAsync(userId);

                if (lastSeen == null)
                {
                    _logger.LogError("No last seen record found for user ID {userId}",userId);
                    return Result<DateTime?>.Failure($"No last seen record found for user ID '{userId}'.");
                }
                _logger.LogInformation("last seen record is found for user");
                return Result<DateTime?>.SuccessResult(lastSeen);
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occurred while retrieving the last seen time");
                return Result<DateTime?>.Failure($"An error occurred while retrieving the last seen time: {ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ApplicationUser>>> GetOnlineUsersAsync()
        {
            try
            {
                var onlineUsers = await _unitOfWork.Users.GetOnlineUsersAsync();

                if (onlineUsers == null || !onlineUsers.Any())
                {
                    _logger.LogWarning("No online users found at this moment.");
                    return Result<IEnumerable<ApplicationUser>>.Failure("No online users found.");
                }

                _logger.LogInformation("Retrieved {Count} online users successfully.", onlineUsers.Count());
                return Result<IEnumerable<ApplicationUser>>.SuccessResult(onlineUsers);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving online users.");
                return Result<IEnumerable<ApplicationUser>>.Failure("An unexpected error occurred while retrieving online users.");
            }
        }


        public async Task<Result<ApplicationUser>> GetUserByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("User ID is null or empty.");
                return Result<ApplicationUser>.Failure("User ID cannot be null or empty.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId, cancellationToken);

                if (user is null)
                {
                    _logger.LogWarning("No user found with ID {UserId}.", userId);
                    return Result<ApplicationUser>.Failure($"User with ID '{userId}' was not found.");
                }

                _logger.LogInformation("Retrieved user with ID {UserId} successfully.", userId);
                return Result<ApplicationUser>.SuccessResult(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving user with ID {UserId}.", userId);
                return Result<ApplicationUser>.Failure("An unexpected error occurred while retrieving the user.");
            }
        }

        public async Task<Result<object>> LoginAsync(LoginDto loginDto)
        {
            _logger.LogInformation("Starting login process for user {Email}", loginDto?.Email);

            if (loginDto == null)
            {
                _logger.LogWarning("Login failed: login data is null");
                return Result<object>.Failure("Login data cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(loginDto.Email) || string.IsNullOrWhiteSpace(loginDto.Password))
            {
                _logger.LogWarning("Login failed: email or password is empty");
                return Result<object>.Failure("Email and password are required.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Email == loginDto.Email);
                if (user == null)
                {
                    _logger.LogWarning("Login failed: no user found with email {Email}", loginDto.Email);
                    return Result<object>.Failure("Invalid email or password.");
                }

                if (await _unitOfWork.Users.IsLockedOutAsync(user))
                {
                    _logger.LogWarning("Login failed: user {Email} is locked out", loginDto.Email);
                    return Result<object>.Failure("User account is locked. Please try again later.");
                }

                if (!await _unitOfWork.Users.CheckPasswordAsync(user, loginDto.Password))
                {
                    _logger.LogWarning("Login failed: invalid credentials for user {Email}", loginDto.Email);
                    return Result<object>.Failure("Invalid email or password.");
                }

                // Generate JWT Access Token
                var accessToken = await _GenerateJwtToken(user);
                if (string.IsNullOrEmpty(accessToken))
                {
                    _logger.LogError("Login failed: unable to generate access token for {Email}", loginDto.Email);
                    return Result<object>.Failure("Failed to generate access token.");
                }

                // Remove old refresh tokens
                await _unitOfWork.Token.DeleteUserRefreshTokensAsync(user.Id.ToString());
                _logger.LogInformation("Old refresh tokens deleted for user {Email}", loginDto.Email);

                // Generate new refresh token
                var refreshToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Token = GenerateSecureToken(),
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow,
                };

                await _unitOfWork.Token.SaveRefreshTokenAsync(refreshToken);
                _logger.LogInformation("New refresh token generated for user {Email}", loginDto.Email);

                // Update user status
                await _unitOfWork.Users.SetStatusAsync(user.Id.ToString(), UserStatus.Online);
                _logger.LogInformation("User {Email} status set to Online", loginDto.Email);

                // Commit changes
                await _unitOfWork.SaveChangesAsync();
                _logger.LogInformation("Login transaction completed successfully for {Email}", loginDto.Email);

                return Result<object>.SuccessResult(new
                {
                    Success = true,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken.Token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during login for {Email}", loginDto?.Email);
                return Result<object>.Failure("An unexpected error occurred during login.");
            }
        }
        public async Task<Result> RegisterAsync(RegisterDto registerDto)
        {
            if (registerDto == null)
            {
                _logger.LogWarning("Registration attempt failed: RegisterDto is null.");
                return Result.Failure("Registration data cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(registerDto.Email) || string.IsNullOrWhiteSpace(registerDto.Password))
            {
                _logger.LogWarning("Registration attempt failed: Missing email or password.");
                return Result.Failure("Email and password are required.");
            }

            try
            {
                if (!_unitOfWork.Users.ValidateEmailFormat(registerDto.Email))
                {
                    _logger.LogWarning("Invalid email format detected for email: {Email}", registerDto.Email);
                    return Result.Failure("Invalid email format.");
                }

                var existingUser = await _unitOfWork.Users.GetAsync(u => u.Email == registerDto.Email);
                if (existingUser != null)
                {
                    _logger.LogWarning("Registration attempt failed: Email {Email} already exists.", registerDto.Email);
                    return Result.Failure("Email is already registered.");
                }

                var user = _mapper.Map<ApplicationUser>(registerDto);
                if (user == null)
                {
                    _logger.LogError("Failed to map RegisterDto to ApplicationUser for email {Email}.", registerDto.Email);
                    return Result.Failure("Failed to map registration data to user entity.");
                }

                user.Status = UserStatus.Offline;
                user.CreatedAt = DateTime.UtcNow;

                var result = await _unitOfWork.Users.CreateAsync(user, registerDto.Password);
                if (!result.Succeeded)
                {
                    var errors = string.Join("; ", result.Errors.Select(x => x.Description));
                    _logger.LogError("User creation failed for {Email}. Errors: {Errors}", registerDto.Email, errors);
                    return Result.Failure($"Failed to create user. Errors: {errors}");
                }

                _logger.LogInformation("User registered successfully with email {Email}.", registerDto.Email);
                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred during registration for email {Email}.", registerDto.Email);
                return Result.Failure("An unexpected error occurred during registration.");
            }
        }


        public async Task<Result> SetUserOfflineAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("SetUserOfflineAsync failed: User ID is null or empty.");
                return Result.Failure("User ID cannot be null or empty.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user is null)
                {
                    _logger.LogWarning("SetUserOfflineAsync: User with ID {UserId} not found.", userId);
                    return Result.Failure($"User with ID '{userId}' does not exist.");
                }

                var updated = await _unitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);
                if (!updated)
                {
                    _logger.LogError("Failed to update user status to Offline for user ID {UserId}.", userId);
                    return Result.Failure("Failed to update user status to Offline.");
                }

                user.LastSeen = DateTimeOffset.UtcNow;
                await _unitOfWork.Users.UpdateAsync(user);

                _logger.LogInformation(
                    "User with ID {UserId} set to Offline successfully at {LastSeen}.",
                    userId,
                    user.LastSeen
                );

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while setting user {UserId} to Offline.", userId);
                return Result.Failure("An unexpected error occurred while setting the user Offline.");
            }
        }

        public async Task<Result> SetUserStatusAsync(string userId, UserStatus status)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("SetUserStatusAsync failed: User ID is null or empty.");
                return Result.Failure("User ID cannot be null or empty.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(x => x.Id.ToString() == userId);

                if (user is null)
                {
                    _logger.LogWarning("SetUserStatusAsync: User with ID {UserId} not found.", userId);
                    return Result.Failure($"User with ID '{userId}' does not exist.");
                }

                var updated = await _unitOfWork.Users.SetStatusAsync(userId, status);
                if (!updated)
                {
                    _logger.LogError("Failed to update status to {Status} for user ID {UserId}.", status, userId);
                    return Result.Failure($"Failed to update user status to {status}.");
                }

                user.LastSeen = DateTimeOffset.UtcNow;
                await _unitOfWork.Users.UpdateAsync(user);

                _logger.LogInformation(
                    "User with ID {UserId} status set to {Status} successfully at {LastSeen}.",
                    userId,
                    status,
                    user.LastSeen
                );

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while setting user {UserId} status to {Status}.", userId, status);
                return Result.Failure("An unexpected error occurred while setting user status.");
            }
        }

        public async Task<Result<bool>> LogoutAsync(string userId, string refreshToken)
        {
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("LogoutAsync failed: User ID is null or empty.");
                return Result<bool>.Failure("User ID cannot be null or empty.");
            }

            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("LogoutAsync failed: Refresh token is null or empty. UserId: {UserId}", userId);
                return Result<bool>.Failure("Refresh token cannot be null or empty.");
            }

            try
            {
                _logger.LogInformation("LogoutAsync started for user {UserId}.", userId);

                var storedToken = await _unitOfWork.Token.GetByTokenAsync(refreshToken);

                if (storedToken == null)
                {
                    _logger.LogWarning("LogoutAsync: No refresh token found for user {UserId}.", userId);
                    return Result<bool>.Failure("Invalid or already revoked refresh token.");
                }

                if (storedToken.isRevoked)
                {
                    _logger.LogWarning("LogoutAsync: Token already revoked for user {UserId}.", userId);
                    return Result<bool>.Failure("Invalid or already revoked refresh token.");
                }

                if (storedToken.UserId.ToString() != userId)
                {
                    _logger.LogWarning("LogoutAsync failed: Token does not belong to user {UserId}. Actual owner: {OwnerId}.", userId, storedToken.UserId);
                    return Result<bool>.Failure("Refresh token does not belong to this user.");
                }

                storedToken.isRevoked = true;
                await _unitOfWork.Token.UpdateRefreshToken(storedToken);
                await _unitOfWork.Token.SaveChangesAsync();

                _logger.LogInformation("Refresh token revoked successfully for user {UserId}.", userId);

                await _unitOfWork.Users.SetStatusAsync(userId, UserStatus.Offline);
                _logger.LogInformation("User {UserId} status set to Offline.", userId);

                await _unitOfWork.Users.LogoutAsync();
                _logger.LogInformation("User {UserId} logged out successfully.", userId);

                return Result<bool>.SuccessResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during logout for user {UserId}.", userId);
                return Result<bool>.Failure("An unexpected error occurred during logout.");
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
            {
                _logger.LogWarning("RefreshTokenAsync failed: Refresh token is null or empty.");
                return Result<object>.Failure("Refresh token cannot be null or empty.");
            }

            try
            {
                _logger.LogInformation("RefreshTokenAsync started.");

                var existingToken = await _unitOfWork.Token.GetByTokenAsync(refreshToken);

                if (existingToken is null)
                {
                    _logger.LogWarning("RefreshTokenAsync failed: Token not found in database.");
                    return Result<object>.Failure("Invalid refresh token.");
                }

                _logger.LogInformation("Refresh token found for user {UserId}.", existingToken.UserId);

                if (existingToken.ExpiresAt <= DateTime.UtcNow)
                {
                    _logger.LogWarning("RefreshTokenAsync failed: Token expired for user {UserId}.", existingToken.UserId);
                    return Result<object>.Failure("Refresh token has expired.");
                }

                if (existingToken.isRevoked)
                {
                    _logger.LogWarning("RefreshTokenAsync failed: Token already revoked for user {UserId}.", existingToken.UserId);
                    return Result<object>.Failure("Refresh token has been revoked.");
                }

                var user = await _unitOfWork.Users.GetAsync(u => u.Id == existingToken.UserId);
                if (user is null)
                {
                    _logger.LogWarning("RefreshTokenAsync failed: No user found for token {TokenId}.", existingToken.Id);
                    return Result<object>.Failure("User not found for this token.");
                }

                _logger.LogInformation("Revoking old refresh token for user {UserId}.", user.Id);
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
                _logger.LogInformation("New refresh token generated successfully for user {UserId}.", user.Id);

                var newAccessToken = await _GenerateJwtToken(user);
                if (string.IsNullOrEmpty(newAccessToken))
                {
                    _logger.LogError("Failed to generate new access token for user {UserId}.", user.Id);
                    return Result<object>.Failure("Failed to generate access token.");
                }

                _logger.LogInformation("Access token refreshed successfully for user {UserId}.", user.Id);

                return Result<object>.SuccessResult(new
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken.Token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while refreshing token.");
                return Result<object>.Failure("An error occurred while refreshing token.");
            }
        }

        public async Task<Result<UserDto>> GetProfileAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("GetProfileAsync failed: User ID is null or empty.");
                return Result<UserDto>.Failure("User ID cannot be null or empty.");
            }

            try
            {
                _logger.LogInformation("Attempting to retrieve profile for user ID {UserId}.", userId);

                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user == null)
                {
                    _logger.LogWarning("No user found with ID {UserId}.", userId);
                    return Result<UserDto>.Failure("User not found.");
                }

                var userDto = _mapper.Map<UserDto>(user);
                if (userDto == null)
                {
                    _logger.LogError("Failed to map ApplicationUser to UserDto for user ID {UserId}.", userId);
                    return Result<UserDto>.Failure("Failed to map user data.");
                }

                _logger.LogInformation("Profile retrieved successfully for user ID {UserId}.", userId);
                return Result<UserDto>.SuccessResult(userDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving the profile for user ID {UserId}.", userId);
                return Result<UserDto>.Failure("An error occurred while retrieving the profile.");
            }
        }

        public async Task<Result<UserDto>> UpdateUserProfileAsync(UserDto updateUserDto, string userId)
        {
            if (updateUserDto == null)
            {
                _logger.LogWarning("UpdateUserProfileAsync failed: User update object is null.");
                return Result<UserDto>.Failure("User update object cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("UpdateUserProfileAsync failed: User ID is null or empty.");
                return Result<UserDto>.Failure("User ID cannot be null or empty.");
            }

            try
            {
                _logger.LogInformation("Attempting to update profile for user ID {UserId}.", userId);

                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user == null)
                {
                    _logger.LogWarning("User with ID {UserId} not found.", userId);
                    return Result<UserDto>.Failure("User not found.");
                }

                var isValidEmailFormat = _unitOfWork.Users.ValidateEmailFormat(updateUserDto.Email);
                if (!isValidEmailFormat)
                {
                    _logger.LogWarning("Invalid email format '{Email}' provided for user ID {UserId}.", updateUserDto.Email, userId);
                    return Result<UserDto>.Failure("Email format is not valid.");
                }

                _logger.LogInformation("Mapping updated data onto user entity for user ID {UserId}.", userId);
                _mapper.Map(updateUserDto, user);
                user.LastSeen = DateTime.UtcNow;

                _logger.LogInformation("Attempting to update user entity in database for user ID {UserId}.", userId);
                var updateResult = await _unitOfWork.Users.UpdateAsync(user);

                if (!updateResult.Succeeded)
                {
                    _logger.LogError(
                        "Failed to update profile for user ID {UserId}. Errors: {Errors}",
                        userId,
                        string.Join(", ", updateResult.Errors.Select(e => e.Description))
                    );

                    return Result<UserDto>.Failure(
                        $"Failed to update user profile. Errors: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
                }

                await _unitOfWork.SaveChangesAsync();
                _logger.LogInformation("User profile updated successfully for user ID {UserId}.", userId);

                // Return the updated profile
                var updatedProfile = await GetProfileAsync(user.Id.ToString());
                _logger.LogInformation("Returning updated profile for user ID {UserId}.", userId);

                return updatedProfile;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while updating profile for user ID {UserId}.", userId);
                return Result<UserDto>.Failure("An error occurred while updating user profile.");
            }
        }

        public async Task<Result<UserDto>> UploadUserImageProfile(string userId, UploadProfileImageDto uploadProfileImageDto)
        {
            if (string.IsNullOrWhiteSpace(userId) ||
                uploadProfileImageDto?.Image == null ||
                uploadProfileImageDto.Image.Length == 0)
            {
                _logger.LogWarning("UploadUserImageProfile failed: Invalid image upload request. UserId: {UserId}", userId);
                return Result<UserDto>.Failure("Invalid image upload request.");
            }

            try
            {
                _logger.LogInformation("Starting profile image upload for user ID {UserId}.", userId);

                var userResult = await GetUserByIdAsync(userId);
                if (!userResult.Success || userResult.Value == null)
                {
                    _logger.LogWarning("UploadUserImageProfile failed: User with ID {UserId} not found.", userId);
                    return Result<UserDto>.Failure("User not found.");
                }

                var user = userResult.Value;

                // Prepare upload directory
                string uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "profile_images");
                if (!Directory.Exists(uploadPath))
                {
                    Directory.CreateDirectory(uploadPath);
                    _logger.LogInformation("Created directory for profile images at {UploadPath}.", uploadPath);
                }

                // Generate unique file name
                var fileName = $"{Guid.NewGuid()}{Path.GetExtension(uploadProfileImageDto.Image.FileName)}";
                var filePath = Path.Combine(uploadPath, fileName);

                _logger.LogInformation("Uploading image for user ID {UserId} to path {FilePath}.", userId, filePath);

                // Save the image file
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await uploadProfileImageDto.Image.CopyToAsync(stream);
                }

                _logger.LogInformation("Image successfully saved for user ID {UserId}. File: {FileName}", userId, fileName);

                // Update user record
                user.ProfileImageUrl = $"/uploads/profile_images/{fileName}";
                var updateResult = await _unitOfWork.Users.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    _logger.LogError("Failed to update user record with new profile image for user ID {UserId}.", userId);
                    return Result<UserDto>.Failure("Failed to update user record with new profile image.");
                }

                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation("User profile image updated successfully for user ID {UserId}.", userId);

                var userDto = _mapper.Map<UserDto>(user);
                if (userDto == null)
                {
                    _logger.LogError("Failed to map updated user entity to UserDto for user ID {UserId}.", userId);
                    return Result<UserDto>.Failure("Failed to map updated user data.");
                }

                _logger.LogInformation("Returning updated user profile (with image) for user ID {UserId}.", userId);
                return Result<UserDto>.SuccessResult(userDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while uploading profile image for user ID {UserId}.", userId);
                return Result<UserDto>.Failure("An error occurred while uploading profile image.");
            }
        }

        public async Task<Result> ForgotPasswordAsync(string email)
        {
            _logger.LogInformation("Starting ForgotPasswordAsync for email: {Email}", email);

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("ForgotPasswordAsync failed: Email is missing or empty.");
                return Result.Failure("Email is required.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("ForgotPasswordAsync: No account found with email {Email}", email);
                    return Result.Failure("No account found with this email.");
                }

                _logger.LogInformation("User found: {UserId}, generating password reset token.", user.Id);

                var token = await _unitOfWork.Users.GeneratePasswordResetTokenAsync(user);
                if (string.IsNullOrWhiteSpace(token))
                {
                    _logger.LogError("ForgotPasswordAsync: Failed to generate reset token for user {UserId}", user.Id);
                    return Result.Failure("Failed to generate reset token.");
                }

                _logger.LogInformation("Reset token successfully generated for user {UserId}", user.Id);

                var encodedToken = Uri.EscapeDataString(token);
                var encodedEmail = Uri.EscapeDataString(email);

                var resetLink = $"{_configuration["ClientUrl"]}AuthUser/reset-password?email={encodedEmail}&token={encodedToken}";
                _logger.LogInformation("Generated reset password link for user {UserId}: {ResetLink}", user.Id, resetLink);

                var subject = "Reset Your Password";
                var body = $@"
                            <h3>Password Reset Request</h3>
                            <p>Hello {user.UserName},</p>
                            <p>Click the link below to reset your password. This link will expire soon:</p>
                            <p><a href='{resetLink}'>Reset Password</a></p>
                            <p>If you didn’t request this, please ignore this email.</p>";

                await _emailService.SendEmailAsync(email, subject, body);
                _logger.LogInformation("Password reset email successfully sent to {Email}", email);

                _logger.LogInformation("ForgotPasswordAsync completed successfully for {Email}", email);
                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while processing forgot password for {Email}", email);
                return Result.Failure($"An error occurred while processing forgot password. Details: {ex.Message}");
            }
        }
        public async Task<Result<string>> ResetPasswordAsync(string email, string token, string newPassword)
        {
            _logger.LogInformation("Starting ResetPasswordAsync for email: {Email}", email);

            if (string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(token) ||
                string.IsNullOrWhiteSpace(newPassword))
            {
                _logger.LogWarning("ResetPasswordAsync failed: One or more required parameters are missing. Email: {Email}, Token: {HasToken}, NewPassword: {HasPassword}",
                    email, !string.IsNullOrWhiteSpace(token), !string.IsNullOrWhiteSpace(newPassword));
                return Result<string>.Failure("Email, token, and new password are required.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("ResetPasswordAsync: No user found for email {Email}", email);
                    return Result<string>.Failure("User not found.");
                }

                _logger.LogInformation("User found for ResetPasswordAsync. UserId: {UserId}", user.Id);

                var decodedToken = Uri.UnescapeDataString(token);
                _logger.LogInformation("ResetPasswordAsync: Token successfully decoded for user {UserId}", user.Id);

                var resetResult = await _unitOfWork.Users.ResetPasswordAsync(user, decodedToken, newPassword);
                if (!resetResult.Succeeded)
                {
                    var errors = string.Join("; ", resetResult.Errors.Select(e => e.Description));
                    _logger.LogError("ResetPasswordAsync failed for user {UserId}. Errors: {Errors}", user.Id, errors);
                    return Result<string>.Failure($"Password reset failed: {errors}");
                }

                _logger.LogInformation("Password successfully reset for user {UserId}", user.Id);

                var stampResult = await _unitOfWork.Users.UpdateSecurityStampAsync(user);
                if (!stampResult.Succeeded)
                {
                    _logger.LogError("ResetPasswordAsync: Failed to update security stamp for user {UserId}", user.Id);
                    return Result<string>.Failure("Failed to update security stamp.");
                }

                _logger.LogInformation("Security stamp updated successfully for user {UserId}", user.Id);
                _logger.LogInformation("ResetPasswordAsync completed successfully for {Email}", email);

                return Result<string>.SuccessResult("Password has been reset successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred during ResetPasswordAsync for {Email}", email);
                return Result<string>.Failure($"Unexpected error occurred: {ex.Message}");
            }
        }

        public async Task<Result> DeleteUserAsync(string email)
        {
            _logger.LogInformation("Starting DeleteUserAsync for email: {Email}", email);

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("DeleteUserAsync failed: Email cannot be null or empty.");
                return Result.Failure("Email cannot be null or empty.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetUserByEmailAsync(email);
                if (user is null)
                {
                    _logger.LogWarning("DeleteUserAsync: User not found for email {Email}", email);
                    return Result.Failure("User not found.");
                }

                _logger.LogInformation("User found for DeleteUserAsync. UserId: {UserId}", user.Id);

                var isDeleted = await _unitOfWork.Users.DeleteAsync(user.Id.ToString());
                if (!isDeleted)
                {
                    _logger.LogError("DeleteUserAsync failed: Could not delete user {UserId}", user.Id);
                    return Result.Failure("Failed to delete user.");
                }

                _logger.LogInformation("User {UserId} deleted successfully.", user.Id);
                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while deleting user with email {Email}", email);
                return Result.Failure("An unexpected error occurred while deleting the user.");
            }
        }

        public async Task<Result<string>> LockUserAsync(string userId)
        {
            _logger.LogInformation("[UserService] Starting LockUserAsync for UserId: {UserId}", userId);

            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("[UserService] LockUserAsync failed: Invalid user ID provided.");
                return Result<string>.Failure("Invalid user ID.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user is null)
                {
                    _logger.LogWarning("[UserService] LockUserAsync: No user found with ID {UserId}", userId);
                    return Result<string>.Failure("User not found.");
                }

                _logger.LogInformation("[UserService] Locking user {UserId}", user.Id);

                _unitOfWork.Users.LockUser(user);
                var changes = await _unitOfWork.SaveChangesAsync();

                if (changes == 0)
                {
                    _logger.LogError("[UserService] LockUserAsync failed: No database changes applied for user {UserId}", user.Id);
                    return Result<string>.Failure("No changes were applied while locking the user.");
                }

                _logger.LogInformation("[UserService] User {UserId} has been locked successfully.", user.Id);
                return Result<string>.SuccessResult("User has been locked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] Unexpected error occurred while locking user {UserId}", userId);
                return Result<string>.Failure($"An unexpected error occurred while locking the user: {ex.Message}");
            }
        }

        public async Task<Result<string>> UnLockUserAsync(string userId)
        {
            _logger.LogInformation("[UserService] Starting UnLockUserAsync for UserId: {UserId}", userId);

            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("[UserService] UnLockUserAsync failed: Invalid user ID provided.");
                return Result<string>.Failure("Invalid user ID.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == userId);
                if (user is null)
                {
                    _logger.LogWarning("[UserService] UnLockUserAsync: No user found with ID {UserId}", userId);
                    return Result<string>.Failure("User not found.");
                }

                _logger.LogInformation("[UserService] Unlocking user {UserId}", user.Id);

                _unitOfWork.Users.UnLockUser(user);
                var changes = await _unitOfWork.SaveChangesAsync();

                if (changes == 0)
                {
                    _logger.LogError("[UserService] UnLockUserAsync failed: No database changes applied for user {UserId}", user.Id);
                    return Result<string>.Failure("No changes were applied while unlocking the user.");
                }

                _logger.LogInformation("[UserService] User {UserId} has been unlocked successfully.", user.Id);
                return Result<string>.SuccessResult("User has been unlocked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] Unexpected error occurred while unlocking user {UserId}", userId);
                return Result<string>.Failure($"An unexpected error occurred while unlocking the user: {ex.Message}");
            }
        }


        public async Task<Result<AdminUpdateUserDto>> UpdateUserProfileAsync(AdminUpdateUserDto dto)
        {
            _logger.LogInformation("[UserService] Starting UpdateUserProfileAsync for user ID: {UserId}", dto?.Id);

            if (dto == null || string.IsNullOrWhiteSpace(dto.Id))
            {
                _logger.LogWarning("[UserService] UpdateUserProfileAsync failed: Invalid request. User ID is required.");
                return Result<AdminUpdateUserDto>.Failure("Invalid request. User ID is required.");
            }

            try
            {
                var user = await _unitOfWork.Users.GetAsync(u => u.Id.ToString() == dto.Id);
                if (user == null)
                {
                    _logger.LogWarning("[UserService] UpdateUserProfileAsync: User not found for ID {UserId}", dto.Id);
                    return Result<AdminUpdateUserDto>.Failure("User not found.");
                }

                _logger.LogInformation("[UserService] Found user {UserId}. Proceeding with profile update.", user.Id);

                // Validate email uniqueness
                if (!string.IsNullOrWhiteSpace(dto.Email) && dto.Email != user.Email)
                {
                    var existingUserByEmail = await _unitOfWork.Users.GetAsync(u => u.Email == dto.Email);
                    if (existingUserByEmail != null)
                    {
                        _logger.LogWarning("[UserService] UpdateUserProfileAsync failed: Email {Email} is already taken.", dto.Email);
                        return Result<AdminUpdateUserDto>.Failure("Email is already taken.");
                    }
                }

                // Validate username uniqueness
                if (!string.IsNullOrWhiteSpace(dto.UserName) && dto.UserName != user.UserName)
                {
                    var existingUserByUsername = await _unitOfWork.Users.GetAsync(u => u.UserName == dto.UserName);
                    if (existingUserByUsername != null)
                    {
                        _logger.LogWarning("[UserService] UpdateUserProfileAsync failed: Username {UserName} is already taken.", dto.UserName);
                        return Result<AdminUpdateUserDto>.Failure("Username is already taken.");
                    }
                }

                _logger.LogInformation("[UserService] Mapping updated data to user entity {UserId}", user.Id);
                _mapper.Map(dto, user);

                // Handle roles
                if (dto.Roles != null && dto.Roles.Any())
                {
                    _logger.LogInformation("[UserService] Updating roles for user {UserId}", user.Id);

                    var currentRoles = await _unitOfWork.Users.GetUserRolesAsync(user);
                    var rolesToAdd = dto.Roles.Except(currentRoles);
                    var rolesToRemove = currentRoles.Except(dto.Roles);

                    foreach (var role in rolesToAdd)
                    {
                        await _unitOfWork.Users.AddToRoleAsync(user, role);
                        _logger.LogInformation("[UserService] Added role '{Role}' to user {UserId}", role, user.Id);
                    }

                    foreach (var role in rolesToRemove)
                    {
                        await _unitOfWork.Users.RemoveFromRoleAsync(user, role);
                        _logger.LogInformation("[UserService] Removed role '{Role}' from user {UserId}", role, user.Id);
                    }
                }

                // Update status if provided
                if (dto.Status.HasValue)
                {
                    user.Status = dto.Status.Value;
                    _logger.LogInformation("[UserService] Updated user {UserId} status to {Status}", user.Id, user.Status);
                }

                _logger.LogInformation("[UserService] Updating security stamp for user {UserId}", user.Id);
                await _unitOfWork.Users.UpdateSecurityStampAsync(user);

                await _unitOfWork.SaveChangesAsync();
                _logger.LogInformation("[UserService] User {UserId} updated successfully in the database.", user.Id);

                var updatedUser = _mapper.Map<AdminUpdateUserDto>(user);
                _logger.LogInformation("[UserService] Returning updated profile for user {UserId}", user.Id);

                return Result<AdminUpdateUserDto>.SuccessResult(updatedUser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] An unexpected error occurred while updating user {UserId}", dto.Id);
                return Result<AdminUpdateUserDto>.Failure($"An unexpected error occurred while updating user: {ex.Message}");
            }
        }

        public async Task<Result<string>> CreateUserAsync(CreateUserByAdminDto dto)
        {
            _logger.LogInformation("[UserService] Starting CreateUserAsync for Email: {Email}", dto?.Email);

            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
            {
                _logger.LogWarning("[UserService] CreateUserAsync failed — Email or Password is empty.");
                return Result<string>.Failure("Email or Password cannot be empty.");
            }

            try
            {
                _logger.LogInformation("[UserService] Checking if user with Email {Email} already exists.", dto.Email);
                var isUserExist = await _unitOfWork.Users.ExistsAsync(x => x.Email == dto.Email);
                if (isUserExist)
                {
                    _logger.LogWarning("[UserService] User with Email {Email} already exists.", dto.Email);
                    return Result<string>.Failure("User already exists.");
                }

                _logger.LogInformation("[UserService] Mapping DTO to ApplicationUser for Email: {Email}", dto.Email);
                var user = _mapper.Map<ApplicationUser>(dto);

                if (dto.ProfileImage is not null && dto.ProfileImage.Length > 0)
                {
                    _logger.LogInformation("[UserService] Uploading profile image for user {Email}", dto.Email);

                    string uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "profile_images");
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                        _logger.LogInformation("[UserService] Created directory: {Path}", uploadsFolder);
                    }

                    var uniqueFileName = $"{Guid.NewGuid()}_{Path.GetFileName(dto.ProfileImage.FileName)}";
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                        await dto.ProfileImage.CopyToAsync(stream);

                    user.ProfileImageUrl = $"/uploads/profile_images/{uniqueFileName}";
                    _logger.LogInformation("[UserService] Profile image uploaded successfully for {Email}", dto.Email);
                }

                _logger.LogInformation("[UserService] Creating user {Email}", dto.Email);
                var result = await _unitOfWork.Users.CreateAsync(user, dto.Password);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("[UserService] Failed to create user {Email}. Errors: {Errors}", dto.Email, errors);
                    return Result<string>.Failure(errors);
                }

                if (dto.Roles != null && dto.Roles.Any())
                {
                    _logger.LogInformation("[UserService] Assigning roles {Roles} to user {Email}", string.Join(", ", dto.Roles), dto.Email);
                    await _unitOfWork.Users.AddToRolesAsync(user, dto.Roles);
                }

                int changeResult = await _unitOfWork.SaveChangesAsync();
                if (changeResult == 0)
                {
                    _logger.LogError("[UserService] Failed to save changes after creating user {Email}", dto.Email);
                    return Result<string>.Failure("Failed to save changes.");
                }

                _logger.LogInformation("[UserService] User {Email} created successfully.", dto.Email);
                return Result<string>.SuccessResult("User created successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] An error occurred while creating user {Email}", dto?.Email);
                return Result<string>.Failure($"An error occurred while creating the user. Details: {ex.Message}");
            }
        }

        public async Task<Result<List<string>>> GetAllRolesAsync()
        {
            _logger.LogInformation("[UserService] Starting GetAllRolesAsync.");

            try
            {
                _logger.LogInformation("[UserService] Fetching all role names from the database.");
                var roles = await _unitOfWork.Users.GetAllRolesNameAsync();

                if (roles == null || !roles.Any())
                {
                    _logger.LogWarning("[UserService] No roles found in the system.");
                    return Result<List<string>>.Failure("No roles found.");
                }

                _logger.LogInformation("[UserService] Retrieved {Count} roles successfully.", roles.Count());
                return Result<List<string>>.SuccessResult(roles.ToList());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] An error occurred while retrieving roles.");
                return Result<List<string>>.Failure($"An error occurred while retrieving roles. Details: {ex.Message}");
            }
        }

        public async Task<Result<string>> RemoveRoleAsync(string roleName)
        {
            _logger.LogInformation("[UserService] Starting RemoveRoleAsync for role: {RoleName}", roleName);

            if (string.IsNullOrWhiteSpace(roleName))
            {
                _logger.LogWarning("[UserService] RemoveRoleAsync called with an invalid role name.");
                return Result<string>.Failure("Role name cannot be null or empty.");
            }

            try
            {
                _logger.LogInformation("[UserService] Attempting to retrieve role '{RoleName}' from the database.", roleName);
                var role = await _unitOfWork.Users.GetRoleAsync(r => r.Name.ToLower() == roleName.ToLower());

                if (role is null)
                {
                    _logger.LogWarning("[UserService] Role '{RoleName}' not found.", roleName);
                    return Result<string>.Failure($"Role '{roleName}' not found.");
                }

                _logger.LogInformation("[UserService] Deleting role '{RoleName}'.", roleName);
                var result = await _unitOfWork.Users.DeleteAsync(role);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("[UserService] Failed to remove role '{RoleName}'. Errors: {Errors}", roleName, errors);
                    return Result<string>.Failure($"Failed to remove role. Errors: {errors}");
                }

                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation("[UserService] Role '{RoleName}' removed successfully.", roleName);
                return Result<string>.SuccessResult($"Role '{roleName}' removed successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserService] An error occurred while removing role '{RoleName}'.", roleName);
                return Result<string>.Failure($"An error occurred while removing the role. Details: {ex.Message}");
            }
        }


    }
}

