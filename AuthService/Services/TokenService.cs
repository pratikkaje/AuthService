using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Entities;
using AuthService.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
namespace AuthService.Services
{
    public class TokenService
    {
        private readonly JwtOptions _jwtOptions;
        private readonly RefreshTokenService _refreshTokenService;
        public TokenService(IOptions<JwtOptions> options, RefreshTokenService refreshTokenService)
        {
            _jwtOptions = options.Value;
            _refreshTokenService = refreshTokenService;
        }

        public async Task<TokenResponse> GenerateTokensAsync(ApplicationUser user)
        {
            var accessToken = GenerateJwt(user);
            var refreshToken = await _refreshTokenService.GenerateRefreshTokenAsync(user);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token
            };
        }

        private string GenerateJwt(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audiences.First(),
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
