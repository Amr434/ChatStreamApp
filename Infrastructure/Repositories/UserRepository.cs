using Application.Interfaces.Repositories;
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
        public UserRepository(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;

        }

        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
           return await _userManager.CheckPasswordAsync(user, password); 
        }

        public async Task<bool> CreateAsync(ApplicationUser user,string password)
        {
           var result= await _userManager.CreateAsync(user,password);
            return result.Succeeded;
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

    }
}
