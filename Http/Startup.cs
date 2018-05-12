#region Related components
using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;

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
			WebHost.CreateDefaultBuilder(args).UseStartup<Startup>().UseKestrel().Build().Run();
			RTU.WebSocket.Dispose();
			WAMPConnections.CloseChannels();
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();
		}

		public IConfiguration Configuration { get; }

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public void ConfigureServices(IServiceCollection services)
		{
			services.AddResponseCompression(options => options.EnableForHttps = true);
			services.AddLogging(builder => builder.SetMinimumLevel(UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Warning")).ToEnum<LogLevel>()));
			services.AddHttpContextAccessor();
			services.AddCache(options => this.Configuration.GetSection("Cache").Bind(options));
			/*
			services.AddSession(options =>
			{
				options.IdleTimeout = TimeSpan.FromMinutes(30);
				options.Cookie.Name = "VIEApps-Session";
				options.Cookie.HttpOnly = true;
			});
			services.AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
				.AddCookie(options =>
				{
					options.Cookie.Name = "VIEApps-Auth";
					options.Cookie.HttpOnly = true;
					options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
					options.SlidingExpiration = true;
				});
			services.AddDataProtection()
				.SetDefaultKeyLifetime(TimeSpan.FromDays(7))
				.SetApplicationName("VIEApps-NGX")
				.UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
				{
					EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
					ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
				});
			*/
			services.Configure<IISOptions>(options =>
			{
				options.ForwardClientCertificate = false;
				options.AutomaticAuthentication = true;
			});
		}

		public void Configure(IApplicationBuilder app)
		{
			var stopwatch = Stopwatch.StartNew();
			Global.ServiceName = "APIGateway";

			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			Logger.AssignLoggerFactory(loggerFactory);

			Global.ServiceProvider = app.ApplicationServices;
			Global.Logger = loggerFactory.CreateLogger<RequestHandler>();

			var logLevel = UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Warning")).ToEnum<LogLevel>();
			var path = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
			{
				path += Path.DirectorySeparatorChar.ToString() + Global.ServiceName.ToLower() + ".http_{Date}.txt";
				loggerFactory.AddFile(path, logLevel);
			}
			else
				path = null;

			var logger = loggerFactory.CreateLogger<Startup>();
			logger.LogInformation($"Start {Global.ServiceName} HTTP service");
			logger.LogDebug($"Logging is enabled [{logLevel}]");
			if (!string.IsNullOrWhiteSpace(path))
				logger.LogDebug($"Rolling log files is enabled [{path}]");

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			var routerInfo = WAMPConnections.GetRouterInfo();
			logger.LogDebug($"Attempting to connect to WAMP router [{routerInfo.Item1}{routerInfo.Item2}]");
			Task.Run(() => InternalAPIs.OpenChannelsAsync()).ConfigureAwait(false);
			InternalAPIs.Cache = new Cache("VIEApps-API-Gateway", this.Configuration.GetAppSetting("Cache/ExpirationTime", 30), this.Configuration.GetAppSetting("Cache/Provider", "Redis"));
			RTU.Initialize(loggerFactory);

			app.UseErrorCodePages();
			app.UseResponseCompression();
			app.UseCache();
			//app.UseSession();
			//app.UseAuthentication();
			app.UseWebSockets(new WebSocketOptions { ReceiveBufferSize = Components.WebSockets.WebSocket.ReceiveBufferSize });
			app.UseMiddleware<RequestHandler>();

			stopwatch.Stop();
			logger.LogInformation($"The {Global.ServiceName} HTTP service is started - Execution times: {stopwatch.GetElapsedTimes()}");
		}
	}
}