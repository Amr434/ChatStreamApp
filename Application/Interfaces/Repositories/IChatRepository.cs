using Application.Interfaces.Repositories;
using ChatApp.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public interface IChatRepository:IRepository<ChatRoom>
    {
        Task<ChatRoom?> GetChatWithUsersAsync(Guid chatId);
        Task<ChatRoom> GetById(string id,params string[] includeProperties);
        Task<ChatRoom?> GetPrivateChatBetweenUsersAsync(string user1id,string user2id);
        Task<IEnumerable<ChatRoom>> GetAllChatRoomForUserAsync(string userid);
        Task<IEnumerable<ChatRoom>> GetRecentChatsAsync(string userid,int limit=10);
    }
}
