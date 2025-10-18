using ChatApp.Domain.Entities;
using System;

namespace ChatApp.Domain.Entities
{
    public class MessageAttachment
    {
        public Guid Id { get; set; }
        public Guid MessageId { get; set; }
        public Message Message { get; set; } = null!;

        public string FileUrl { get; set; } = null!;
        public string FileType { get; set; } = null!;
        public long FileSize { get; set; }
    }
}
