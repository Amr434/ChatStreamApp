using Application.Interfaces;
using Application.Interfaces.Repositories;
using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Persistence;
using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly ApplicationDbContext _context;
        public IUserRepository Users { get; }
        public ITokenRepository Token { get; }
        public UnitOfWork(
                ApplicationDbContext context,
                IUserRepository userRepository,
                ITokenRepository tokenRepository)
        {
            _context = context;
            Users = userRepository;
            Token = tokenRepository;
        }       
        public async Task<int> SaveChangesAsync()
        {
           return await  _context.SaveChangesAsync();
        }
    }
}
