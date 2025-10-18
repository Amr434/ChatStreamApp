using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;

namespace ChatApp.Domain.Entities
{
    public class UserChat
    {
        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;
        
        public Guid ChatRoomId { get; set; }
        public ChatRoom ChatRoom { get; set; } = null!;

        public bool IsAdmin { get; set; } = false;
        public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
    }
}
