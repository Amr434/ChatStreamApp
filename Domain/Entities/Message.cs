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
        public bool IsDeleted { get; set; }

        public DateTime SentAt { get; set; } = DateTime.UtcNow;
        public DateTime? EditedAt { get; set; }

        public MessageType Type { get; set; } = MessageType.Text;

        public Guid? ParentMessageId { get; set; }
        public Message? ParentMessage { get; set; }
        public ICollection<Message>? Replies { get; set; }

        public ICollection<MessageAttachment>? Attachments { get; set; }
        public ICollection<MessageReaction>? Reactions { get; set; }
        public ICollection<MessageStatus>? MessageStatuses { get; set; }  
    }

    public enum MessageType
    {
        Text = 0,
        Image = 1,
        File = 2,
        Voice = 3,
        Video = 4,
        System = 5
    }
}
