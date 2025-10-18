using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.User
{
   public class VerifyEmailRequest
    {
      public  string Email { get; set; }
      public  string Token {  get;set; }
    }
}
