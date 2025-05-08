using System.Text;
using System.Text.Json;
using AuthService.Models;
using Microsoft.Extensions.Logging;

namespace AuthService.Services
{
    public class EmailService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<EmailService> _logger;
        private readonly string _apiUrl =
            Environment.GetEnvironmentVariable("EmailUrl") + Environment.GetEnvironmentVariable("EmailToken");

        public EmailService(HttpClient httpClient, ILogger<EmailService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<bool> SendEmailAsync(EmailContent emailContent)
        {
            _logger.LogInformation("Starting to send email to {Recipient}.", emailContent.To);

            try
            {
                var jsonContent = JsonSerializer.Serialize(emailContent);
                var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                _logger.LogDebug("Serialized email content: {EmailContent}", jsonContent);

                var response = await _httpClient.PostAsync(_apiUrl, httpContent);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Email sent successfully to {Recipient}.", emailContent.To);
                    return true;
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    _logger.LogWarning("Failed to send email to {Recipient}. Status Code: {StatusCode}, Error: {Error}",
                        emailContent.To, response.StatusCode, error);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while sending email to {Recipient}.", emailContent.To);
                return false;
            }
        }
    }
}
