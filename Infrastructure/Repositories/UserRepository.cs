using Application.Common.Model;
using Application.Interfaces.Repositories;
using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;
using Domain.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public class UserRepository: IUserRepository
    {
       private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        public UserRepository(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,RoleManager<ApplicationRole> roleManager
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
           return await _userManager.CheckPasswordAsync(user, password); 
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user,string password)
        {
           return await _userManager.CreateAsync(user,password);
        }
        public async Task<bool> DeleteAsync(string userId)
        {
            var user = await GetAsync(x=>x.Id.ToString()== userId);
            if (user == null) return false;

           var result= await _userManager.DeleteAsync(user);
            return result.Succeeded;
        }

        public async Task<bool> ExistsAsync(string userId)
        {
           var user= await GetAsync(x=>x.Id.ToString()== userId);
            if (user == null)
                return false;
            return true;
        }

        public async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
        {
            if(user is null)
                throw new ArgumentNullException(nameof(user));
            return await _userManager.GeneratePasswordResetTokenAsync(user);
        }

        public async Task<IEnumerable<ApplicationUser>> GetAllAsync()
        {
            return await _userManager.Users.ToListAsync();
        }
        public async Task<ApplicationUser?> GetAsync(Expression<Func<ApplicationUser,bool >> predicate, CancellationToken cancellationToken=default)
        {
            return await _userManager.Users.FirstOrDefaultAsync(predicate,cancellationToken);
        }
        public async Task<DateTime?> GetLastSeenAsync(string userId)
        {
            var user= await GetAsync(x=> x.Id.ToString()== userId);
            return user?.LastSeen.UtcDateTime;
        }
        public async Task<IEnumerable<ApplicationUser>> GetOnlineUsersAsync()
        {
            return await _userManager.Users.Where(x=>x.Status==UserStatus.Online).ToListAsync();
        }

        public async Task<IList<string>> GetUserRolesAsync(ApplicationUser user)
        {
           return await _userManager.GetRolesAsync(user);
        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }      

        public async Task<bool> SetStatusAsync(string userId, UserStatus status)
        {
            var user= await GetAsync(x=>x.Id.ToString()== userId);

            if (user == null)
                return false;

            user.Status= status;
            var result =await UpdateAsync(user);

            return result.Succeeded;
        }
        public async Task<IdentityResult> UpdateAsync(ApplicationUser user)
        {
           return await _userManager.UpdateAsync(user);
        }

        public  bool ValidateEmailFormat(string email)
        {
           var emailAddressAttribute = new EmailAddressAttribute();
            if (emailAddressAttribute.IsValid(email))
                return true;
            return false;
        }
        public async Task<ApplicationUser?> GetUserByEmailAsync(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentNullException(nameof(email));
            return await _userManager.FindByEmailAsync(email);
        }
        public async Task<IdentityResult> ResetPasswordAsync(ApplicationUser user,string token,string newPassword)
        {
            return await _userManager.ResetPasswordAsync(user, token, newPassword);
        }
        public async Task<IdentityResult> UpdateSecurityStampAsync(ApplicationUser user)
        {
           return await _userManager.UpdateSecurityStampAsync(user);
        }
        public async Task<IdentityResult> DeleteUserAsync(string email)
        {
            var user =await GetUserByEmailAsync(email);
          return await _userManager.DeleteAsync(user);
        }
        public void LockUser(ApplicationUser user)
        {
            user.LockoutEnd = DateTimeOffset.UtcNow.AddYears(100);
        }
        public void UnLockUser(ApplicationUser user)
        {
            user.LockoutEnd = null;
        }

        public async Task AddToRoleAsync(ApplicationUser user, string role)
        {
          await  _userManager.AddToRoleAsync(user, role);
        }

        public async Task RemoveFromRoleAsync(ApplicationUser user, string role)
        {
            await _userManager.RemoveFromRoleAsync(user, role);
        }

        public async Task<bool> ExistsAsync(Expression<Func<ApplicationUser, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await _userManager.Users.AnyAsync(predicate, cancellationToken);
        }
        public async Task AddToRolesAsync(ApplicationUser user, IEnumerable<string> roles)
        {
           await _userManager.AddToRolesAsync(user, roles);
        }

        public async Task<IEnumerable<string>> GetAllRolesNameAsync()
        {
            return await _roleManager.Roles
                .Select(r => r.Name)
                .ToListAsync();
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationRole role)
        {
           return await _roleManager.DeleteAsync(role);
        }

        public async Task<ApplicationRole> GetRoleAsync(Expression<Func<ApplicationRole, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await _roleManager.Roles.FirstAsync(predicate, cancellationToken);
        }

        public async Task<bool> IsLockedOutAsync(ApplicationUser user)
        {
            return await _userManager.IsLockedOutAsync(user);
        }

        public async Task<IEnumerable<ApplicationUser>> GetAllAsync(Expression<Func<ApplicationUser, bool>> predicate)
        {
            return await _userManager.Users
                .Where(predicate)
                .AsNoTracking()
                .ToListAsync();
        }

    }
}
