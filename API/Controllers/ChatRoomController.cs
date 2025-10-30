using Application.Common.Model;
using Application.DTOs.Chat;
using Application.Services.Chat;
using ChatApp.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ChatRoomController : ControllerBase
    {
        IChatRoomService _chatRoomService;
        public ChatRoomController(IChatRoomService chatRoomService)
        {
            _chatRoomService = chatRoomService;
        }
        [HttpPost("add-user")]
        public async Task<IActionResult> AddUserToGroupChatAsync([FromBody]AddUserToGroupChatDto dto)
        {
            if (dto is null)
                return BadRequest(new
                {
                    Success = false,
                    Message = "Request body cannot be null."
                });

            if (string.IsNullOrWhiteSpace(dto.chatRoomId) || string.IsNullOrWhiteSpace(dto.userId))
                return BadRequest(new
                {
                    Success = false,
                    Message = "ChatRoomId and UserId are required."
                });

            var result = await _chatRoomService.AddUserToGroupChatAsync(dto);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error
                });

            return Ok(new
            {
                Success = true,
                Message = result.Value ?? "User added successfully to the group chat."
            });
        }

        [HttpPost("create-group")]
        public async Task<IActionResult> CreateGroupChatAsync([FromBody]CreateGroupChatDto dto
            )
        {
            if (dto is null)
                return BadRequest(new
                {
                    Success = false,
                    Message = "Request body cannot be null.",
                });
            var result = await _chatRoomService.CreateGroupChatAsync(dto);
            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error??"An Error Happen when Create Group Chat",
                });
            return Ok(new
            {
                Success = true,
                Message = result.Value
            });
        }

        [HttpDelete("delete{ChatRoomId}")]
        public async Task<IActionResult> DeleteChatRoom(string ChatRoomId)
        {
            if (string.IsNullOrEmpty(ChatRoomId))
                return BadRequest(new
                {
                    Success = false,
                    Message = ""
                });
           var result = await _chatRoomService.DeleteChatRoomAsync(ChatRoomId);

            if(!result.Success)
                return NotFound(new
                {
                    Success = false,
                    Message= result.Error
                });

            return Ok(new
            {
                Success = true,
                Message = result.Value ?? "Chat Room Is Deleted Successfully"
            });
        }
        [HttpPut("demote")]
        public async Task<IActionResult> DemoteUserFromAdminAsync(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrWhiteSpace(userId))
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "Chat room ID and message ID cannot be null or empty."
                });
            }

            var result = await _chatRoomService.DemoteUserFromAdminAsync(chatRoomId, userId);

            if (!result.Success)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "An error occurred while demoting the user."
                });
            }

            return Ok(new
            {
                Success = true,
                Message = result.Value ?? 
                "User has been successfully demoted from admin."
            });
        }

        [HttpGet("all-chat-user")]
        public async Task<IActionResult> GetAllChatRoomsForUserAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "User ID cannot be null or empty."
                });
            }

            var result = await _chatRoomService.GetAllChatRoomsForUserAsync(userId);

            if (!result.Success)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "Failed to retrieve chat rooms for the user."
                });
            }

            return Ok(new
            {
                Success = true,
                ChatRooms = result.Value 
            });
        }

        [HttpGet("{ChatRoomId}")]
        public async Task<IActionResult>GetChatById(string ChatRoomId)
        {
            if (string.IsNullOrEmpty(ChatRoomId))
                return BadRequest(new
                {
                    Success = false,
                    Message = "Chat Room Id Is Null Or Empty"
                });

          var result = await _chatRoomService.GetChatRoomByIdAsync(ChatRoomId);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Error = result.Error
                });

            return Ok(new
            {
                Success = true,
                ChatRoom = result.Value
            });      
        }

        [HttpGet("group-chat-members/{chatRoomId}")]
        public async Task<IActionResult> GetGroupChatMembersAsync(string chatRoomId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId))
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "Chat room ID cannot be null or empty."
                });
            }

            var result = await _chatRoomService.GetChatRoomByIdAsync(chatRoomId);

            if (!result.Success)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "Failed to retrieve chat room members."
                });
            }

            return Ok(new
            {
                Success = true,
                Group = result.Value 
            });
        }

        [HttpGet("Recent-Chats/{userId}/{limit}")] 
        public async Task<IActionResult> GetRecentChatsAsync(string  userId, int limit = 10)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return BadRequest(new
                {
                    Success = false,
                    Message = "user id is null or empty"
                });

           var result = await _chatRoomService.GetRecentChatsAsync(userId, limit);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Members = result.Value
                });
            return Ok(new
            {
                Success = true,
                RecentChats = result.Value
            });
        }

        [HttpPut("promote-user-to-admin")]
        public async Task<IActionResult> PromoteUserToAdmin(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrEmpty(userId))
                return BadRequest(new
                {
                    Success = false,
                    Error = "chat room Id is null or empty"
                });
           var result = await _chatRoomService.PromoteUserToAdminAsync(chatRoomId, userId);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error??"an error occured"
                });

            return Ok(new
            {
                Success = true,
                Message = "user is Prommoted successfully"
            });

        }
        [HttpDelete("remove-user-from-group")]
        public async Task<IActionResult> RemoveUserFromGroupChat(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrEmpty(userId))
                return BadRequest(new
                {
                    Success = false,
                    Message = "chatroomid and userid is null or emtpy"
                });
           var result = await _chatRoomService.RemoveUserFromGroupChatAsync(chatRoomId, userId);

            if (!result.Success)
                return BadRequest(new 
                { 
                    Success = false,
                    Message =  result.Error??"user removed successfully"
                });

            return Ok(new
            {
                Success= true,
                Message="user removed successfully"
            });
        }
        [HttpGet("search-chat-rooms")]
        public async Task<ActionResult<IEnumerable<ChatRoomListDto>>> SearchChatRoomsAsync(string keyword, string userId)
        {
            if (string.IsNullOrEmpty(keyword) || string.IsNullOrEmpty(userId))
                return BadRequest(new
                {
                    Success = false,
                    Message = "userid and keyword is null or empty"
                });

           var result = await _chatRoomService.SearchChatRoomsAsync(keyword, userId);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Message = $"{result.Error}"
                });
            return Ok(new
            {
                Success = true,
                ChatRooms = result.Value
            });
        }

        [HttpPut("set-last-message")]
        public async Task<IActionResult> SetLastMessageAsync(string chatRoomId, string messageId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrWhiteSpace(messageId))
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "Chat room ID and message ID cannot be null or empty."
                });
            }

            var result = await _chatRoomService.SetLastMessageAsync(chatRoomId, messageId);

            if (!result.Success)
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "Failed to set the last message."
                });

            return Ok(new
            {
                Success = true,
                Message = "Last message set successfully."
            });
        }
        [HttpPut("update")]
        public async Task<IActionResult> UpdateChatRoomAsync([FromBody] UpdateChatRoomDto dto)
        {
            if (dto is null)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "Request body cannot be null."
                });
            }

            var result = await _chatRoomService.UpdateChatRoomAsync(dto);

            if (!result.Success)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = result.Error ?? "An error occurred while updating the chat room."
                });
            }

            return Ok(new
            {
                Success = true,
                Message = "Chat room updated successfully."
            });
        }

    }
}
