using AuthService.Data;
using AuthService.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Services
{
    public class RefreshTokenService
    {
        private readonly AppDbContext _context;

        public RefreshTokenService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<RefreshToken> GenerateRefreshTokenAsync(ApplicationUser user)
        {
            var token = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                UserId = user.Id,
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            };
            _context.Add(token);
            await _context.SaveChangesAsync();
            return token;
        }

        public async Task<ApplicationUser> GetUserFromRefreshTokenAsync(string refreshToken)
        {
            var token = await _context.RefreshTokens
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Token == refreshToken && t.ExpiryDate > DateTime.UtcNow);

            return token?.User;
        }
    }
}
