using ChatApp.Infrastructure.Identity;
using System;
using System.Collections.Generic;

namespace ChatApp.Domain.Entities
{
    public class ChatRoom
    {
        public Guid Id { get; set; }

        public string Name { get; set; } = null!;
        public string? Description { get; set; }

        public bool IsGroup { get; set; }

        public Guid? CreatedById { get; set; }
        public ApplicationUser? CreatedBy { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }

        // 🔹 Optional: for display image or group icon
        public string? ProfileImageUrl { get; set; }

        // 🔹 Optional: for "last message preview"
        public Guid? LastMessageId { get; set; }
        public Message? LastMessage { get; set; }

        // 🔹 Navigation
        public ICollection<UserChat>? UserChats { get; set; }   // Many-to-many link with users
        public ICollection<Message>? Messages { get; set; }
    }
}
