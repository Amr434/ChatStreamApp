using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.Chat
{
   public class AddUserToGroupChatDto
    {
        public string chatRoomId { get; set; }

        public string userId { get; set; }

        public bool isAdmin { get; set; } = false;
    }
}
