using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;
using System;
using System.Collections.Generic;

namespace ChatApp.Domain.Entities
{
    public class Message
    {
        public Guid Id { get; set; }
        public Guid ChatRoomId { get; set; }
        public ChatRoom ChatRoom { get; set; } = null!;

        public Guid SenderId { get; set; }
        public ApplicationUser Sender { get; set; } = null!;

        public string Content { get; set; } = null!;
        public bool IsEdited { get; set; }
        public DateTime SentAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public ICollection<MessageAttachment>? Attachments { get; set; }
        public ICollection<MessageReaction>? Reactions { get; set; }
        public ICollection<MessageStatus>? MessageStatuses { get; set; }
    }
}
