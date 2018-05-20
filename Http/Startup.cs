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
			// setup console
			if (Environment.UserInteractive)
				Console.OutputEncoding = Encoding.UTF8;

			// host the HTTP with Kestrel
			WebHost.CreateDefaultBuilder(args)
				.UseStartup<Startup>()
				.UseKestrel()
				.UseUrls((args.FirstOrDefault(a => a.IsStartsWith("/listenuri:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/listenuri:", "").Trim() ?? UtilityService.GetAppSetting("HttpUri:Listen", "http://0.0.0.0:8024")))
				.Build()
				.Run();

			// dispose objects
			Global.InterCommunicateMessageUpdater?.Dispose();
			WAMPConnections.CloseChannels();
			RTU.Dispose();

			Global.RSA.Dispose();
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();
			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is stopped");
		}

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		public void ConfigureServices(IServiceCollection services)
		{
			// mandatory services
			services.AddResponseCompression(options => options.EnableForHttps = true);
			services.AddLogging(builder => builder.SetMinimumLevel(UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information")).ToEnum<LogLevel>()));
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

		public void Configure(IApplicationBuilder app, IHostingEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Global.ServiceName = "APIGateway";

			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			var logLevel = UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information")).ToEnum<LogLevel>();
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
			Global.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? $"Windows {RuntimeInformation.OSArchitecture}" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? $"Linux {RuntimeInformation.OSArchitecture}" : $"Other {RuntimeInformation.OSArchitecture} OS")} ({RuntimeInformation.OSDescription.Trim()})");
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
			app.UseStatusCodeHandler();
			app.UseResponseCompression();
			app.UseCache();
			app.UseWebSockets(new WebSocketOptions
			{
				ReceiveBufferSize = Components.WebSockets.WebSocket.ReceiveBufferSize,
				KeepAliveInterval = RTU.WebSocket.KeepAliveInterval
			});
			app.UseMiddleware<Handler>();

			// caching & logging
			InternalAPIs.Cache = new Cache("VIEApps-API-Gateway", this.Configuration.GetAppSetting("Cache/ExpirationTime", 30), false, this.Configuration.GetAppSetting("Cache/Provider", "Redis"), loggerFactory);
			InternalAPIs.Logger = loggerFactory.CreateLogger<Handler.InternalAPIs>();
			RTU.Logger = loggerFactory.CreateLogger<Handler.RTU>();

			// final
			if (environment.IsDevelopment())
				Global.Logger.LogInformation($"Listening URI: {UtilityService.GetAppSetting("HttpUri:Listen")}");
			Global.Logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterInfo().Item1}");
			Global.Logger.LogInformation($"API Gateway HTTP service URI: {UtilityService.GetAppSetting("HttpUri:APIs")}");
			Global.Logger.LogInformation($"Files HTTP service URI: {UtilityService.GetAppSetting("HttpUri:Files")}");
			Global.Logger.LogInformation($"Users HTTP service URI: {UtilityService.GetAppSetting("HttpUri:Users")}");
			Global.Logger.LogInformation($"Root path: {Global.RootPath}");
			Global.Logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
			Global.Logger.LogInformation($"Default logging level: {logLevel}");
			if (!string.IsNullOrWhiteSpace(path))
				Global.Logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
			Global.Logger.LogInformation($"Static files path: {UtilityService.GetAppSetting("Path:StaticFiles")}");
			Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
			Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");

			stopwatch.Stop();
			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - Execution times: {stopwatch.GetElapsedTimes()}");
			Global.Logger = loggerFactory.CreateLogger<Handler>();
		}
	}
}