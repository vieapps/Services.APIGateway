#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;

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
			RTU.WebSocket.Dispose();
			WAMPConnections.CloseChannels();
			Global.InterCommunicateMessageUpdater?.Dispose();
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();
			Global.RSA.Dispose();
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
			services.Configure<IISOptions>(options =>
			{
				options.ForwardClientCertificate = false;
				options.AutomaticAuthentication = true;
			});
		}

		public void Configure(IApplicationBuilder app)
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
			Global.Logger.LogInformation($"Logging is enabled [{logLevel}]");
			if (!string.IsNullOrWhiteSpace(path))
				Global.Logger.LogInformation($"Rolling log files is enabled [{path}]");

			Global.ServiceProvider = app.ApplicationServices;
			Global.CreateRSA();

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
			InternalAPIs.Cache = new Cache("VIEApps-API-Gateway", this.Configuration.GetAppSetting("Cache/ExpirationTime", 30), this.Configuration.GetAppSetting("Cache/Provider", "Redis"));
			InternalAPIs.Logger = loggerFactory.CreateLogger<Handler.InternalAPIs>();
			RTU.Logger = loggerFactory.CreateLogger<Handler.RTU>();

			// done
			stopwatch.Stop();
			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - Execution times: {stopwatch.GetElapsedTimes()}");
			Global.Logger = loggerFactory.CreateLogger<Handler>();
		}
	}
}