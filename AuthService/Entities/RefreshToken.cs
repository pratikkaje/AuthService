using System.ComponentModel.DataAnnotations;

namespace AuthService.Entities
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public string Token { get; set; }
        public string UserId { get; set; }
        public DateTime ExpiryDate { get; set; }

        public ApplicationUser User { get; set; }
    }
}
