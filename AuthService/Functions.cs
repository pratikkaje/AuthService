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
        private readonly EmailService _emailService;
        private readonly ILogger<Functions> _logger;

        public Functions(UserManager<ApplicationUser> userManager,
            TokenService tokenService,
            RefreshTokenService refreshTokenService,
            SignInManager<ApplicationUser> signInManager,
            ILogger<Functions> logger,
            EmailService emailService)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _refreshTokenService = refreshTokenService;
            _signInManager = signInManager;
            _logger = logger;
            _emailService = emailService;
        }

        [Function("Register")]
        public async Task<HttpResponseData> Register(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/register")] HttpRequestData req)
        {
            try
            {
                var request = await JsonSerializer.DeserializeAsync<RegisterRequest>(req.Body);

                if (request == null)
                {
                    _logger.LogWarning("Invalid registration request received.");
                    var badRequestResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await badRequestResponse.WriteStringAsync("Invalid request payload.");
                    return badRequestResponse;
                }

                var user = new ApplicationUser { Email = request.Email, UserName = request.Email };
                var result = await _userManager.CreateAsync(user, request.Password);

                if (result.Succeeded)
                {

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var encodedToken = Uri.EscapeDataString(token);

                    var mobileAppUrl = Environment.GetEnvironmentVariable("MobileAppUrl"); // Replace with your frontend app's base URL
                    var verificationLink = $"{mobileAppUrl}/verify-email?userId={user.Id}&token={encodedToken}";

                    var emailContent = new EmailContent
                    {
                        To = user.Email,
                        Subject = "Verify Your Email",
                        Body = $"Click the link to verify your email: {verificationLink}"
                    };

                    var isEmailSent = await _emailService.SendEmailAsync(emailContent);
                    if (isEmailSent)
                    {
                        Console.WriteLine("Email sent successfully.");
                    }
                    else
                    {
                        Console.WriteLine("Failed to send email.");
                    }
                }

                var response = req.CreateResponse(result.Succeeded ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
                await response.WriteAsJsonAsync(result);
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during user registration.");
                var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                await errorResponse.WriteStringAsync("An error occurred while processing your request.");
                return errorResponse;
            }
        }

        [Function("VerifyEmail")]
        public async Task<HttpResponseData> VerifyEmail(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/verify-email")] HttpRequestData req)
        {
            _logger.LogInformation("VerifyEmail function triggered.");

            try
            {
                // Parse the request body
                var request = await JsonSerializer.DeserializeAsync<VerifyEmailRequest>(req.Body);
                if (request == null || string.IsNullOrEmpty(request.UserId) || string.IsNullOrEmpty(request.Token))
                {
                    _logger.LogWarning("Invalid verify-email request. Missing userId or token.");
                    var badRequestResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await badRequestResponse.WriteStringAsync("Invalid request. Missing userId or token.");
                    return badRequestResponse;
                }

                _logger.LogInformation("Attempting to verify email for userId: {UserId}", request.UserId);

                // Find the user by ID
                var user = await _userManager.FindByIdAsync(request.UserId);
                if (user == null)
                {
                    _logger.LogWarning("User not found for userId: {UserId}", request.UserId);
                    var notFoundResponse = req.CreateResponse(HttpStatusCode.NotFound);
                    await notFoundResponse.WriteStringAsync("User not found.");
                    return notFoundResponse;
                }

                // Confirm the email
                var result = await _userManager.ConfirmEmailAsync(user, request.Token);
                if (result.Succeeded)
                {
                    _logger.LogInformation("Email successfully verified for userId: {UserId}", request.UserId);
                    var successResponse = req.CreateResponse(HttpStatusCode.OK);
                    await successResponse.WriteStringAsync("Email successfully verified.");
                    return successResponse;
                }
                else
                {
                    _logger.LogWarning("Email verification failed for userId: {UserId}. Errors: {Errors}",
                        request.UserId, string.Join(", ", result.Errors.Select(e => e.Description)));
                    var badRequestResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await badRequestResponse.WriteStringAsync("Email verification failed.");
                    return badRequestResponse;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during email verification.");
                var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                await errorResponse.WriteStringAsync("An error occurred while processing your request.");
                return errorResponse;
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

        [Function("DeleteUser")]
        public async Task<HttpResponseData> DeleteUser(
            [HttpTrigger(AuthorizationLevel.Function, "delete", Route = "auth/delete-user")] HttpRequestData req)
        {
            _logger.LogInformation("DeleteUser function triggered.");

            try
            {
                var request = await JsonSerializer.DeserializeAsync<DeleteUserRequest>(req.Body);
                if (request == null || string.IsNullOrEmpty(request.Email))
                {
                    _logger.LogWarning("Invalid delete-user request. Missing or invalid email.");
                    var badRequestResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await badRequestResponse.WriteStringAsync("Invalid request. Email is required.");
                    return badRequestResponse;
                }

                _logger.LogInformation("Attempting to delete user with email: {Email}", request.Email);

                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    _logger.LogWarning("User not found for email: {Email}", request.Email);
                    var notFoundResponse = req.CreateResponse(HttpStatusCode.NotFound);
                    await notFoundResponse.WriteStringAsync("User not found.");
                    return notFoundResponse;
                }

                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User successfully deleted with email: {Email}", request.Email);
                    var successResponse = req.CreateResponse(HttpStatusCode.OK);
                    await successResponse.WriteStringAsync("User successfully deleted.");
                    return successResponse;
                }
                else
                {
                    _logger.LogWarning("Failed to delete user with email: {Email}. Errors: {Errors}",
                        request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                    var badRequestResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await badRequestResponse.WriteStringAsync("Failed to delete user.");
                    return badRequestResponse;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while deleting the user.");
                var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                await errorResponse.WriteStringAsync("An error occurred while processing your request.");
                return errorResponse;
            }
        }
    }
}
