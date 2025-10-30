using ChatApp.Infrastructure.Identity;
using System;

namespace ChatApp.Domain.Entities
{
    public class UserChat
    {
        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;

        public Guid ChatRoomId { get; set; }
        public ChatRoom ChatRoom { get; set; } = null!;

        public ChatRole Role { get; set; } = ChatRole.Member;
        public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastSeenAt { get; set; }
        public DateTime? MutedUntil { get; set; }
        public bool IsMuted => MutedUntil.HasValue && MutedUntil > DateTime.UtcNow;
        public bool IsAdmin { get; set; } = false;
    }

    public enum ChatRole
    {
        Member = 0,
        Admin = 1,
        Owner = 2
    }
}
