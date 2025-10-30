using System;

namespace Application.DTOs.Chat
{
    public class ChatRoomListDto
    {
        public string ChatRoomId { get; set; } = null!;

        public string Name { get; set; } = null!;
        public string? Description { get; set; }

        public bool IsGroup { get; set; }
        public string? ProfileImageUrl { get; set; }

        public string? LastMessageContent { get; set; }
        public string? LastMessageSenderName { get; set; }
        public DateTime? LastMessageSentAt { get; set; }

        public int UnreadCount { get; set; }

        // For private chats: who is the other user
        public string? OtherUserId { get; set; }
        public string? OtherUserName { get; set; }
        public string? OtherUserImageUrl { get; set; }

        public bool IsOnline { get; set; }

        // Optional: activity tracking
        public DateTime? LastActivityAt { get; set; }
    }
}
