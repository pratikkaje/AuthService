﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Models
{
    public class VerifyEmailRequest
    {
        public string UserId { get; set; }
        public string Token { get; set; }
    }
}
