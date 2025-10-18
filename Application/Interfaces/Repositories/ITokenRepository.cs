using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.Repositories
{
    public interface ITokenRepository
    {
        Task SaveRefreshTokenAsync(RefreshToken token);
        Task<RefreshToken?> GetValidRefreshTokenAsync(string userId);
        Task<RefreshToken?> GetByTokenAsync(string token);
        Task DeleteUserRefreshTokensAsync(string userId);
        Task RevokeTokenAsync(string token);
        Task SaveChangesAsync();
        Task UpdateRefreshToken(RefreshToken refreshToken);
    }
}
