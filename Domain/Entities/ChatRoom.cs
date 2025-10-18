using System;
using System.Collections.Generic;

namespace ChatApp.Domain.Entities
{
    public class ChatRoom
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        public bool IsGroup { get; set; }
        public string? Description { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public ICollection<UserChat>? UserChats { get; set; }
        public ICollection<Message>? Messages { get; set; }
    }
}
