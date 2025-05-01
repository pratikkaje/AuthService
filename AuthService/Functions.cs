using System.Net;
using System.Text.Json;
using AuthService.Entities;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace AuthService
{
    public class Functions
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly TokenService _tokenService;
        private readonly RefreshTokenService _refreshTokenService;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<Functions> _logger;

        public Functions(UserManager<ApplicationUser> userManager,
            TokenService tokenService,
            RefreshTokenService refreshTokenService,
            SignInManager<ApplicationUser> signInManager,
            ILogger<Functions> logger)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _refreshTokenService = refreshTokenService;
            _signInManager = signInManager;
            _logger = logger;
        }

        [Function("Register")]
        public async Task<HttpResponseData> Register(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/register")] HttpRequestData req)
        {
            try
            {
                var request = await JsonSerializer.DeserializeAsync<RegisterRequest>(req.Body);
                var user = new ApplicationUser { Email = request.Email, UserName = request.Email };
                var result = await _userManager.CreateAsync(user, request.Password);

                var response = req.CreateResponse(result.Succeeded ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
                await response.WriteAsJsonAsync(result);
                return response;
            }
            catch (Exception ex)
            {

                throw ex;
            }

        }

        [Function("Login")]
        public async Task<HttpResponseData> Login(
                    [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/login")] HttpRequestData req)
        {
            var request = await JsonSerializer.DeserializeAsync<LoginRequest>(req.Body);
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                var response = req.CreateResponse(HttpStatusCode.Unauthorized);
                await response.WriteStringAsync("Invalid credentials.");
                return response;
            }

            var tokens = await _tokenService.GenerateTokensAsync(user);

            var success = req.CreateResponse(HttpStatusCode.OK);
            await success.WriteAsJsonAsync(tokens);
            return success;
        }

        [Function("ForgotPassword")]
        public async Task<HttpResponseData> ForgotPassword(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/forgot-password")] HttpRequestData req)
        {
            var request = await JsonSerializer.DeserializeAsync<ForgotPasswordRequest>(req.Body);
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                var response = req.CreateResponse(HttpStatusCode.BadRequest);
                await response.WriteStringAsync("User not found.");
                return response;
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var success = req.CreateResponse(HttpStatusCode.OK);
            await success.WriteStringAsync(token);
            return success;
        }

        [Function("ResetPassword")]
        public async Task<HttpResponseData> ResetPassword(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/reset-password")] HttpRequestData req)
        {
            var request = await JsonSerializer.DeserializeAsync<ResetPasswordRequest>(req.Body);
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                var response = req.CreateResponse(HttpStatusCode.BadRequest);
                await response.WriteStringAsync("User not found.");
                return response;
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

            var success = req.CreateResponse(result.Succeeded ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
            await success.WriteAsJsonAsync(result);
            return success;
        }

        [Function("RefreshToken")]
        public async Task<HttpResponseData> RefreshToken(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/refresh-token")] HttpRequestData req)
        {
            var request = await JsonSerializer.DeserializeAsync<RefreshRequest>(req.Body);
            var user = await _refreshTokenService.GetUserFromRefreshTokenAsync(request.RefreshToken);

            if (user == null)
            {
                var response = req.CreateResponse(HttpStatusCode.Unauthorized);
                await response.WriteStringAsync("Invalid refresh token.");
                return response;
            }

            var tokens = await _tokenService.GenerateTokensAsync(user);
            var success = req.CreateResponse(HttpStatusCode.OK);
            await success.WriteAsJsonAsync(tokens);
            return success;
        }
    }
}
