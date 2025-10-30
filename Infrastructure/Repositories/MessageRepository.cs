using Application.Interfaces.Repositories;
using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Persistence;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
   public class MessageRepository:Repository<Message>,IMessageRepository
    {
        private readonly ApplicationDbContext _dbContext;
        public MessageRepository(ApplicationDbContext dbContext):base(dbContext)
        {
            _dbContext= dbContext;
        }
    }
}
