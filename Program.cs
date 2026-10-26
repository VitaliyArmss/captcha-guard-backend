using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient("Turnstile", client =>
{
    client.Timeout = TimeSpan.FromSeconds(12);
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("captcha-verify", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    await next();
});
app.UseRateLimiter();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/captcha/config", (IConfiguration config) =>
{
    var siteKey = config["Turnstile:SiteKey"];
    var secretKey = config["Turnstile:SecretKey"];
    var secretMessage = config["App:SecretMessage"];
    var configured = !string.IsNullOrWhiteSpace(siteKey)
                     && !string.IsNullOrWhiteSpace(secretKey)
                     && !string.IsNullOrWhiteSpace(secretMessage);

    return Results.Ok(new
    {
        siteKey = string.IsNullOrWhiteSpace(siteKey) ? null : siteKey,
        configured
    });
});

app.MapPost("/api/captcha/verify", async (
    VerifyRequest request,
    HttpContext httpContext,
    IConfiguration config,
    IHttpClientFactory httpClientFactory) =>
{
    httpContext.Response.Headers["Cache-Control"] = "no-store, no-cache, max-age=0";
    httpContext.Response.Headers["Pragma"] = "no-cache";

    var siteKey = config["Turnstile:SiteKey"];
    var secretKey = config["Turnstile:SecretKey"];
    var secretMessage = config["App:SecretMessage"];

    if (string.IsNullOrWhiteSpace(siteKey)
        || string.IsNullOrWhiteSpace(secretKey)
        || string.IsNullOrWhiteSpace(secretMessage))
    {
        return (IResult)Results.Problem(
            title: "Сервис не настроен",
            detail: "Настройте Turnstile:SiteKey, Turnstile:SecretKey и App:SecretMessage в конфигурации backend.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    if (string.IsNullOrWhiteSpace(request.Token) || request.Token.Length > 2048)
    {
        return (IResult)Results.BadRequest(new { success = false, message = "Не получен корректный токен CAPTCHA. Обновите проверку и повторите попытку." });
    }

    var remoteIp = httpContext.Connection.RemoteIpAddress;
    var values = new Dictionary<string, string>
    {
        ["secret"] = secretKey,
        ["response"] = request.Token
    };
    if (remoteIp is not null && !IPAddress.IsLoopback(remoteIp))
        values["remoteip"] = remoteIp.ToString();

    try
    {
        var client = httpClientFactory.CreateClient("Turnstile");
        using var response = await client.PostAsync(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            new FormUrlEncodedContent(values),
            httpContext.RequestAborted);

        if (!response.IsSuccessStatusCode)
        {
            return (IResult)Results.Problem(
                title: "Сервис CAPTCHA временно недоступен",
                statusCode: StatusCodes.Status502BadGateway);
        }

        var result = await response.Content.ReadFromJsonAsync<SiteverifyResponse>(
            cancellationToken: httpContext.RequestAborted);

        if (result is null || !result.Success)
        {
            return (IResult)Results.BadRequest(new
            {
                success = false,
                message = "Cloudflare не подтвердил CAPTCHA. Обновите проверку и попробуйте ещё раз."
            });
        }

        var expectedHostname = config["Turnstile:ExpectedHostname"];
        if (!string.IsNullOrWhiteSpace(expectedHostname)
            && !string.Equals(result.Hostname, expectedHostname, StringComparison.OrdinalIgnoreCase))
        {
            return (IResult)Results.BadRequest(new { success = false, message = "Проверка отклонена: имя хоста не совпало." });
        }

        if (!string.Equals(result.Action, "reveal_secret", StringComparison.Ordinal))
        {
            return (IResult)Results.BadRequest(new { success = false, message = "Проверка отклонена: действие CAPTCHA не совпало." });
        }

        return (IResult)Results.Ok(new { success = true, secret = secretMessage });
    }
    catch (OperationCanceledException) when (!httpContext.RequestAborted.IsCancellationRequested)
    {
        return (IResult)Results.Problem(title: "Истекло время ожидания Cloudflare", statusCode: StatusCodes.Status504GatewayTimeout);
    }
    catch (HttpRequestException)
    {
        return (IResult)Results.Problem(title: "Не удалось связаться с Cloudflare", statusCode: StatusCodes.Status502BadGateway);
    }
});

// Development-only automation endpoint for testing the C# collector without solving CAPTCHA.
// It is unavailable outside Development, requires a separate local key, and accepts loopback requests only.
if (app.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("Automation:Enabled"))
{
    app.MapPost("/api/lab/secret", (HttpContext context, IConfiguration config) =>
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp is null || !IPAddress.IsLoopback(remoteIp))
            return (IResult)Results.NotFound();

        var expectedKey = config["Automation:ApiKey"];
        var suppliedKey = context.Request.Headers["X-Lab-Automation-Key"].ToString();
        if (string.IsNullOrWhiteSpace(expectedKey) || !FixedTimeEquals(expectedKey, suppliedKey))
            return (IResult)Results.Unauthorized();

        var secretMessage = config["App:SecretMessage"];
        if (string.IsNullOrWhiteSpace(secretMessage))
            return (IResult)Results.Problem(title: "Не задана секретная строка", statusCode: StatusCodes.Status503ServiceUnavailable);

        context.Response.Headers["Cache-Control"] = "no-store, no-cache, max-age=0";
        return (IResult)Results.Ok(new { success = true, secret = secretMessage, mode = "development-lab" });
    }).RequireRateLimiting("captcha-verify");
}

app.Run();

static bool FixedTimeEquals(string expected, string supplied)
{
    var expectedBytes = Encoding.UTF8.GetBytes(expected);
    var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    return expectedBytes.Length == suppliedBytes.Length
        && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
}

sealed record VerifyRequest(string? Token);

sealed class SiteverifyResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; init; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; init; }

    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("error-codes")]
    public string[]? ErrorCodes { get; init; }
}
