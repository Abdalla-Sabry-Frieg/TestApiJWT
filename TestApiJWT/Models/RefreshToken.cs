using Microsoft.EntityFrameworkCore;

namespace TestApiJWT.Models
{
    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiresOn { get; set; }
        public bool IsExpired => DateTime.UtcNow >= ExpiresOn; 
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokedOn { get; set; } // the time Stopped on 
        public bool IsActive => RevokedOn == null && !IsExpired;  // IsExpire == false // RevokedOn == null Means => Token still work 
    }
}
