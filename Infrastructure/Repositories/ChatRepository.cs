using ChatApp.Domain.Entities;
using Application.Interfaces.Repositories;
using ChatApp.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories
{
    public class ChatRepository : Repository<ChatRoom>, IChatRepository
    {
        private readonly ApplicationDbContext _context;

        public ChatRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }

 

        public async Task<IEnumerable<ChatRoom>> GetAllChatRoomForUserAsync(string userId)
        {
            return await _context.chatRooms
                .AsNoTracking()
                .Include(cr => cr.UserChats)
                .Where(cr => cr.UserChats.Any(uc => uc.UserId.ToString() == userId))
                .ToListAsync();
        }

        public async Task<ChatRoom> GetById(string id, params string[] includes)
        {
          IQueryable<ChatRoom>queryable = _context.chatRooms.AsQueryable();
            if (includes != null || includes.Any())
            {
                foreach (var includeProperty in includes)
                {
                    queryable = queryable.Include(includeProperty.Trim());
                }
            }
            return await queryable.FirstOrDefaultAsync(c => c.Id.ToString() == id);
        }

        public async Task<ChatRoom?> GetChatWithUsersAsync(Guid chatId)
        {
            return await _context.chatRooms
                .Include(c => c.UserChats)
                .ThenInclude(uc => uc.User)
                .Include(c => c.Messages)
                .FirstOrDefaultAsync(c => c.Id == chatId);
        }

        public async Task<ChatRoom?> GetPrivateChatBetweenUsersAsync(string user1Id, string user2Id)
        {
            var user1Guid = Guid.Parse(user1Id);
            var user2Guid = Guid.Parse(user2Id);

            return await _context.chatRooms
                .FirstOrDefaultAsync(cr =>
                    !cr.IsGroup &&
                    cr.UserChats.Any(u => u.UserId == user1Guid) &&
                    cr.UserChats.Any(u => u.UserId == user2Guid));
        }

        public async Task<IEnumerable<ChatRoom>> GetRecentChatsAsync(string userid, int limit = 10)
        {
                    
           return await _context.chatRooms
                    .Include(x => x.UserChats)
                    .Where(y => y.UserChats.Any(x => x.UserId.ToString() == userid)).Take(limit).ToListAsync();
        }
    }
}
