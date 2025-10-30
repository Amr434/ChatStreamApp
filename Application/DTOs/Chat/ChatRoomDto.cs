using Application.DTOs.User;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.Chat
{
    public class ChatRoomDto
    {
        public string Name { get; set; } = null!;
        public bool IsGroup { get; set; }
        public string? Description { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<UserChatDto> Members { get; set; } = new();
    }
}
