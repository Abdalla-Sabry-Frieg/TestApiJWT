using System.ComponentModel.DataAnnotations;

namespace TestApiJWT.Models
{
    public class AddRoleModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string RoleName { get; set; }
        
        [Required]
        public string UserName { get; set; }
    }
}
