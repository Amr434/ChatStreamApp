using Application.Interfaces.Repositories;
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
        Task<int> SaveChangesAsync();
    }

}
