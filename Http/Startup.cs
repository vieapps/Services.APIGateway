#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Caching.Distributed;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Startup
	{
		public static void Main(string[] args)
		{
			WebHost.CreateDefaultBuilder(args)
				.CaptureStartupErrors(true)
				.UseStartup<Startup>()
				.UseKestrel()
				.UseUrls(args.FirstOrDefault(a => a.IsStartsWith("/listenuri:"))?.Replace("/listenuri:", "").Trim() ?? UtilityService.GetAppSetting("HttpUri:Listen", "http://0.0.0.0:8024"))
				.Build()
				.Run();
		}

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		public void ConfigureServices(IServiceCollection services)
		{
			services.AddResponseCompression(options => options.EnableForHttps = true);
			services.AddLogging(builder => builder.SetMinimumLevel(this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information").ToEnum<LogLevel>()));
			services.AddCache(options => this.Configuration.GetSection("Cache").Bind(options));
			services.AddHttpContextAccessor();

			// IIS integration
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				services.Configure<IISOptions>(options =>
				{
					options.ForwardClientCertificate = false;
					options.AutomaticAuthentication = false;
				});
		}

		public void Configure(IApplicationBuilder app, IApplicationLifetime appLifetime, IHostingEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Console.OutputEncoding = Encoding.UTF8;
			Global.ServiceName = "APIGateway";

			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			var logLevel = this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information").ToEnum<LogLevel>();
			var path = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}" + $"_{Global.ServiceName.ToLower()}.http.txt");
				loggerFactory.AddFile(path, logLevel);
			}
			else
				path = null;

			Logger.AssignLoggerFactory(loggerFactory);
			Global.Logger = loggerFactory.CreateLogger<Startup>();

			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");
			Global.Logger.LogInformation($"Version: {typeof(Startup).Assembly.GetVersion()}");
			Global.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
#if DEBUG
			Global.Logger.LogInformation($"Working mode: DEBUG ({(environment.IsDevelopment() ? "Development" : "Production")})");
#else
			Global.Logger.LogInformation($"Working mode: RELEASE ({(environment.IsDevelopment() ? "Development" : "Production")})");
#endif

			Global.CreateRSA();
			Global.ServiceProvider = app.ApplicationServices;
			Global.RootPath = environment.ContentRootPath;

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// WAMP & RTU
			InternalAPIs.OpenWAMPChannels();
			RTU.Initialize();

			// middleware
			if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				app.UseForwardedHeaders(new ForwardedHeadersOptions
				{
					ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
				});
			app.UseCache();
			app.UseStatusCodeHandler();
			app.UseResponseCompression();
			app.UseWebSockets(new WebSocketOptions
			{
				ReceiveBufferSize = Components.WebSockets.WebSocket.ReceiveBufferSize,
				KeepAliveInterval = RTU.WebSocket.KeepAliveInterval
			});
			app.UseMiddleware<Handler>();

			// caching & logging
			InternalAPIs.Cache = app.ApplicationServices.GetService<ICache>();
			InternalAPIs.Logger = loggerFactory.CreateLogger<Handler.InternalAPIs>();
			RTU.Logger = loggerFactory.CreateLogger<Handler.RTU>();

			// on started
			appLifetime.ApplicationStarted.Register(() =>
			{
				if (environment.IsDevelopment() || Environment.UserInteractive)
					Global.Logger.LogInformation($"Listening URI: {UtilityService.GetAppSetting("HttpUri:Listen", "http://0.0.0.0:8024")}");
				Global.Logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterStrInfo()}");
				Global.Logger.LogInformation($"API Gateway HTTP service URI: {UtilityService.GetAppSetting("HttpUri:APIs")}");
				Global.Logger.LogInformation($"Files HTTP service URI: {UtilityService.GetAppSetting("HttpUri:Files")}");
				Global.Logger.LogInformation($"Users HTTP service URI: {UtilityService.GetAppSetting("HttpUri:Users")}");
				Global.Logger.LogInformation($"Root path: {Global.RootPath}");
				Global.Logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
				Global.Logger.LogInformation($"Default logging level: {logLevel} [ASP.NET Core always set logging level by value of appsettings.json]");
				if (!string.IsNullOrWhiteSpace(path))
					Global.Logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
				Global.Logger.LogInformation($"Static files path: {UtilityService.GetAppSetting("Path:StaticFiles")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();

				Global.InterCommunicateMessageUpdater?.Dispose();
				WAMPConnections.CloseChannels();
				RTU.Dispose();

				Global.RSA.Dispose();
				Global.CancellationTokenSource.Cancel();
			});

			// on stopped
			appLifetime.ApplicationStopped.Register(() =>
			{
				Global.CancellationTokenSource.Dispose();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is stopped");
			});

			// don't terminate the process immediately, wait for the Main thread to exit gracefully
			Console.CancelKeyPress += (sender, args) =>
			{
				appLifetime.StopApplication();
				args.Cancel = true;
			};
		}
	}
}