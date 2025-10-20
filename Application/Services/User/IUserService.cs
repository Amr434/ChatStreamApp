using Application.Common.Model;
using Application.DTOs.User;
using ChatApp.Infrastructure.Identity;
using Domain.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Services.User
{
        public interface IUserService
        {
            Task<Result> RegisterAsync(RegisterDto registerDto);

            Task<Result<Object>> LoginAsync(LoginDto loginDto);

            Task<Result<ApplicationUser>> GetUserByIdAsync(string userId, CancellationToken cancellationToken = default);

            Task<Result<IEnumerable<ApplicationUser>>> GetAllUsersAsync(CancellationToken cancellationToken = default);

            Task<Result<IEnumerable<ApplicationUser>>> GetOnlineUsersAsync(CancellationToken cancellationToken = default);

            Task<Result> SetUserStatusAsync(string userId, UserStatus status);

            Task<Result> SetUserOfflineAsync(string userId);

            Task<Result<DateTime?>> GetLastSeenAsync(string userId);

            Task<Result<bool>> ExistsAsync(string userId);
            Task<Result<bool>> LogoutAsync(string userId,string RefreshToken);
        public Task<Result<object>> RefreshTokenAsync(string refreshToken);
        public Task<Result<UserDto>> GetProfileAsync(string UserId);

        public Task<Result<UserDto>> UpdateUserProfileAsync(UserDto userDto,string userId);
        public Task<Result<UserDto>> UploadUserImageProfile(string userId, UploadProfileImageDto uploadProfileImageDto);
        public Task<Result> ForgotPasswordAsync(string email);
        public Task<Result<string>> ResetPasswordAsync(string email, string token, string newPassword);
        public Task<Result> DeleteUserAsync(string email);
        public Task<Result<string>> LockUserAsync(string id);
        public Task<Result<string>> UnLockUserAsync(string userId);
        public Task<Result<AdminUpdateUserDto>> UpdateUserProfileAsync(AdminUpdateUserDto adminUpdateUser);
        public Task<Result<string>> CreateUserAsync(CreateUserByAdminDto createUserByAdminDto);

        public Task<Result<List<string>>> GetAllRolesAsync();
        public Task<Result<string>> RemoveRoleAsync(string roleName);


    }
}
