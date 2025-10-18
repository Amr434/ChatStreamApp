using Application.Interfaces.Repositories;
using ChatApp.Infrastructure.Identity;
using ChatApp.Infrastructure.Persistence;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public class TokenRepository : ITokenRepository
    {
        private readonly ApplicationDbContext _context;

        public TokenRepository(ApplicationDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task DeleteUserRefreshTokensAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentNullException(nameof(userId));

            var tokens = await _context.RefreshTokens
                .Where(x => x.UserId.ToString() == userId)
                .ToListAsync();

            if (!tokens.Any())
                return; 

            _context.RefreshTokens.RemoveRange(tokens);
            await SaveChangesAsync();
        }

        public async Task<RefreshToken?> GetByTokenAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token));

            return await _context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(x => x.Token == token);
        }

        public async Task<RefreshToken?> GetValidRefreshTokenAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentNullException(nameof(userId));

            var result= await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.UserId.ToString() == userId && !x.isRevoked && x.ExpiresAt<DateTime.UtcNow);
            return result;
        }

        public async Task RevokeTokenAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token));

            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == token);

            if (refreshToken == null)
                throw new InvalidOperationException("Refresh Token not Found");

            refreshToken.isRevoked = true;
            _context.RefreshTokens.Update(refreshToken);
            await SaveChangesAsync();
        }

        public async Task SaveChangesAsync()
        {
           await _context.SaveChangesAsync();
        }

        public async Task SaveRefreshTokenAsync(RefreshToken token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var existingToken = await GetValidRefreshTokenAsync(token.UserId.ToString());

                if (existingToken != null)
                {
                    existingToken.isRevoked = true;
                    _context.RefreshTokens.Update(existingToken);
                }

                await _context.RefreshTokens.AddAsync(token);
                await _context.SaveChangesAsync();

                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task UpdateRefreshToken(RefreshToken refreshToken)
        {
            if(refreshToken == null)
                throw new ArgumentNullException(nameof(refreshToken));
            _context.RefreshTokens.Update(refreshToken);
            await SaveChangesAsync();
        }

        
    }
}
