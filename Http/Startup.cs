#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
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
			// setup console
			if (Environment.UserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

			// run the web host with Kestrel
			WebHost.CreateDefaultBuilder(args)
				.UseStartup<Startup>()
				.UseKestrel()
				.UseUrls($"http://0.0.0.0:{args.FirstOrDefault(a => a.IsStartsWith("/port:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/port:", "").Trim() ?? "8030"}")
				.Build()
				.Run();

			// dispose objects
			RTU.WebSocket.Dispose();
			WAMPConnections.CloseChannels();
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();
			Global.RSA.Dispose();
		}

		public IConfiguration Configuration { get; }

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public void ConfigureServices(IServiceCollection services)
		{
			// mandatory services
			services.AddResponseCompression(options => options.EnableForHttps = true);
			services.AddLogging(builder => builder.SetMinimumLevel(UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information")).ToEnum<LogLevel>()));
			services.AddHttpContextAccessor();
			services.AddCache(options => this.Configuration.GetSection("Cache").Bind(options));

			/*
			 // session state
			services.AddSession(options =>
			{
				options.IdleTimeout = TimeSpan.FromMinutes(30);
				options.Cookie.Name = "VIEApps-Session";
				options.Cookie.HttpOnly = true;
			});

			// authentication
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

			// IIS integration
			services.Configure<IISOptions>(options =>
			{
				options.ForwardClientCertificate = false;
				options.AutomaticAuthentication = true;
			});
		}

		public void Configure(IApplicationBuilder app)
		{
			// mandatory settings
			var stopwatch = Stopwatch.StartNew();
			Global.ServiceName = "APIGateway";

			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger<Startup>();
			logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");

			Logger.AssignLoggerFactory(loggerFactory);
			Global.Logger = loggerFactory.CreateLogger<Handler>();
			Global.ServiceProvider = app.ApplicationServices;
			Global.CreateRSA();

			var logLevel = UtilityService.GetAppSetting("Logs:Level", this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information")).ToEnum<LogLevel>();
			var path = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
			{
				path += Path.DirectorySeparatorChar.ToString() + Global.ServiceName.ToLower() + ".http_{Date}.txt";
				loggerFactory.AddFile(path, logLevel);
			}
			else
				path = null;

			logger.LogInformation($"Logging is enabled [{logLevel}]");
			if (!string.IsNullOrWhiteSpace(path))
				logger.LogInformation($"Rolling log files is enabled [{path}]");

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// initialize middlewares
			app.UseErrorCodePages();
			app.UseResponseCompression();
			app.UseCache();
			//app.UseSession();
			//app.UseAuthentication();
			app.UseWebSockets(new WebSocketOptions { ReceiveBufferSize = Components.WebSockets.WebSocket.ReceiveBufferSize });
			app.UseMiddleware<Handler>();

			// initialize service
			InternalAPIs.Cache = new Cache("VIEApps-API-Gateway", this.Configuration.GetAppSetting("Cache/ExpirationTime", 30), this.Configuration.GetAppSetting("Cache/Provider", "Redis"));
			InternalAPIs.OpenWAMPChannels();
			RTU.Initialize();

			// done
			stopwatch.Stop();
			logger.LogInformation($"The {Global.ServiceName} HTTP service is started - Execution times: {stopwatch.GetElapsedTimes()}");
		}
	}
}