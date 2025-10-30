using System;

namespace Application.DTOs.Chat
{
    public class UserChatDto
    {
        public string UserId { get; set; } = null!;
        public string UserName { get; set; } = null!;
        public string? FullName { get; set; }
        public string? ProfileImageUrl { get; set; }

        public bool IsAdmin { get; set; }
        public bool IsMuted { get; set; } 
        public DateTime JoinedAt { get; set; }

        public bool IsOnline { get; set; }
        public DateTime? LastSeen { get; set; }
    }
}
