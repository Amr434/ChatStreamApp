using Application.Interfaces;
using Application.Interfaces.Repositories;
using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Persistence;
using Domain.Entities;
using Infrastructure.Repositories;
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

        public IChatRepository ChatRoomRepository { get; }

        public IMessageRepository MessageRepository { get; }

        public UnitOfWork(
                ApplicationDbContext context,
                IUserRepository userRepository,
                ITokenRepository tokenRepository,
                IChatRepository chat)
        {
            _context = context;
            Users = userRepository;
            Token = tokenRepository;
            ChatRoomRepository = chat;
        }       
        public async Task<int> SaveChangesAsync()
        {
           return await  _context.SaveChangesAsync();
        }
    }
}
