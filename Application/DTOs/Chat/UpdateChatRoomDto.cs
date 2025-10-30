using Application.DTOs.User;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.Chat
{
    public class UpdateChatRoomDto
    {
        public string chatRoomId { get; set; } = null!;
        public string Name { get; set; } = null!;
        public bool IsGroup { get; set; }
        public string? imageUrl { get; set; }
        public bool? isPrivate { get; set; } 
       
    }
}
