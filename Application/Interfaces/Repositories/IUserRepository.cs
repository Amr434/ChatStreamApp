using Application.Common.Model;
using Application.DTOs.User;
using ChatApp.Infrastructure.Identity;
using Domain.Enums;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.Repositories
{
    public interface IUserRepository
    {

        public Task<ApplicationUser?> GetAsync(Expression<Func<ApplicationUser,bool>> predicate,CancellationToken cancellationToken=default);
        Task<IEnumerable<ApplicationUser>> GetAllAsync();
        Task<IEnumerable<ApplicationUser>> GetOnlineUsersAsync();
        Task<bool> CreateAsync(ApplicationUser user,string password);
        Task<IdentityResult> UpdateAsync(ApplicationUser user);
        Task<bool> DeleteAsync(string userId);
        Task<bool> SetStatusAsync(string userId, UserStatus status);
        Task<DateTime?> GetLastSeenAsync(string userId);
        Task<bool> ExistsAsync(string userId);
        bool ValidateEmailFormat(string email);
        Task<bool> CheckPasswordAsync(ApplicationUser user, string password);
        public Task LogoutAsync();

        public Task<IList<string>> GetUserRolesAsync(ApplicationUser user);
        public Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user);

        public Task<ApplicationUser?> GetUserByEmailAsync(string email);

        public Task<IdentityResult> ResetPasswordAsync(ApplicationUser user, string token, string newPassword);
        public Task<IdentityResult> UpdateSecurityStampAsync(ApplicationUser user);

    }
}
