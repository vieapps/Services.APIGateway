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
using Microsoft.Extensions.Hosting;
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
		public static void Main(string[] args) => WebHost.CreateDefaultBuilder(args).Run<Startup>(args, 8024);

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		LogLevel LogLevel => this.Configuration.GetAppSetting("Logging/LogLevel/Default", UtilityService.GetAppSetting("Logs:Level", "Information")).ToEnum<LogLevel>();

		public void ConfigureServices(IServiceCollection services)
		{
			services
				.AddResponseCompression(options => options.EnableForHttps = true)
				.AddLogging(builder => builder.SetMinimumLevel(this.LogLevel))
				.AddCache(options => this.Configuration.GetSection("Cache").Bind(options))
				.AddHttpContextAccessor();
		}

		public void Configure(IApplicationBuilder appBuilder, IHostApplicationLifetime appLifetime, IWebHostEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Console.OutputEncoding = Encoding.UTF8;
			Global.ServiceName = "APIGateway";
			AspNetCoreUtilityService.ServerName = UtilityService.GetAppSetting("ServerName", "VIEApps NGX");
			Components.WebSockets.WebSocket.AgentName = $"{UtilityService.GetAppSetting("ServerName", "VIEApps NGX")} WebSockets";

			var loggerFactory = appBuilder.ApplicationServices.GetService<ILoggerFactory>();
			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}" + $"_{Global.ServiceName.ToLower()}.http.all.txt");
				loggerFactory.AddFile(logPath, this.LogLevel);
			}
			else
				logPath = null;

			Logger.AssignLoggerFactory(loggerFactory);
			Global.Logger = loggerFactory.CreateLogger<Startup>();
			InternalAPIs.Logger = loggerFactory.CreateLogger<Handler.InternalAPIs>();
			RTU.Logger = loggerFactory.CreateLogger<Handler.RTU>();

			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");
			Global.Logger.LogInformation($"Version: {typeof(Startup).Assembly.GetVersion()}");
#if DEBUG
			Global.Logger.LogInformation($"Working mode: DEBUG ({(environment.IsDevelopment() ? "Development" : "Production")})");
#else
			Global.Logger.LogInformation($"Working mode: RELEASE ({(environment.IsDevelopment() ? "Development" : "Production")})");
#endif
			Global.Logger.LogInformation($"Environment:\r\n\t- User: {Environment.UserName.ToLower()} @ {Environment.MachineName.ToLower()}\r\n\t- Platform: {Extensions.GetRuntimePlatform()}");
			Global.Logger.LogInformation($"Service URIs:\r\n\t- Round robin: services.{Global.ServiceName.ToLower()}.http\r\n\t- Single (unique): services.{Extensions.GetUniqueName(Global.ServiceName + ".http")}");

			Global.CreateRSA();
			Global.ServiceProvider = appBuilder.ApplicationServices;
			Global.RootPath = environment.ContentRootPath;

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// connect to API Gateway Router
			Router.Connect();

			var enableForwarder = "true".IsEquals(UtilityService.GetAppSetting("Router:Forwarder", "false"));
			if (enableForwarder)
				Router.InitializeForwarder();

			// setup the real-time updater
			RTU.Initialize();

			// setup the middlewares
			appBuilder
				.UseForwardedHeaders(Global.GetForwardedHeadersOptions())
				.UseCache()
				.UseStatusCodeHandler()
				.UseResponseCompression()
				.UseWebSockets(new WebSocketOptions
				{
					ReceiveBufferSize = Components.WebSockets.WebSocket.ReceiveBufferSize,
					KeepAliveInterval = RTU.WebSocket.KeepAliveInterval
				});

			// setup the forwarder of API Gateway Router
			if (enableForwarder)
			{
				appBuilder.Map("/router", builder => Router.RegisterForwarderTransport(builder));
				Router.OpenForwarder();
			}

			// setup the handler for all requests
			appBuilder.UseMiddleware<Handler>();

			// setup the caching storage
			InternalAPIs.Cache = appBuilder.ApplicationServices.GetService<ICache>();

			// assign app event handler => on started
			appLifetime.ApplicationStarted.Register(() =>
			{
				Global.Logger.LogInformation($"API Gateway Router: {new Uri(Services.Router.GetRouterStrInfo()).GetResolvedURI()}");
				if (enableForwarder)
					Global.Logger.LogInformation($"Forwarder of API Gateway Router: {UtilityService.GetAppSetting("HttpUri:APIs")}/router");

				Global.Logger.LogInformation($"API Gateway HTTP service: {UtilityService.GetAppSetting("HttpUri:APIs", "None")}");
				Global.Logger.LogInformation($"Files HTTP service: {UtilityService.GetAppSetting("HttpUri:Files", "None")}");
				Global.Logger.LogInformation($"Portals HTTP service: {UtilityService.GetAppSetting("HttpUri:Portals", "None")}");
				Global.Logger.LogInformation($"Passports HTTP service: {UtilityService.GetAppSetting("HttpUri:Passports", "None")}");
				Global.Logger.LogInformation($"Root (base) directory: {Global.RootPath}");
				Global.Logger.LogInformation($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
				Global.Logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:StaticFiles", "None")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Logging level: {this.LogLevel} - Rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");
				Global.Logger.LogInformation($"Request body limit: {UtilityService.GetAppSetting("Limits:Body", "10")} MB");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// assign app event handler => on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();
				Router.Disconnect();
				if (enableForwarder)
					Router.CloseForwarder();
				RTU.Dispose();
				Global.RSA.Dispose();
				Global.CancellationTokenSource.Cancel();
			});

			// assign app event handler => on stopped
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