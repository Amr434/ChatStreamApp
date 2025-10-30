using Application.Interfaces.Repositories;
using Infrastructure.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces
{
    public interface IUnitOfWork
    {
        IUserRepository Users {get;}
        ITokenRepository Token {get;}
        IChatRepository ChatRoomRepository {get;}
        IMessageRepository MessageRepository {get;}
        Task<int> SaveChangesAsync();
        
    }

}
