namespace AuthService.Models
{
    public class JwtOptions
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public List<string> Audiences { get; set; }
    }
}
