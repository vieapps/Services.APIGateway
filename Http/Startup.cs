#region Related components
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using WampSharp.V2.Realm;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Startup
	{
		public static void Main(string[] args)
			=> WebHost.CreateDefaultBuilder(args).Run<Startup>(args, 8024);

		public Startup(IConfiguration configuration)
			=> this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		LogLevel LogLevel => this.Configuration.GetAppSetting("Logging/LogLevel/Default", UtilityService.GetAppSetting("Logs:Level", "Information")).TryToEnum(out LogLevel logLevel) ? logLevel : LogLevel.Information;

		public void ConfigureServices(IServiceCollection services)
		{
			services
				.AddResponseCompression(options => options.EnableForHttps = true)
				.AddLogging(builder => builder.SetMinimumLevel(this.LogLevel))
				.AddCache(options => this.Configuration.GetSection("Cache").Bind(options))
				.AddHttpContextAccessor();
			if (Global.UseIISInProcess)
				services.Configure<IISServerOptions>(options => Global.PrepareIISServerOptions(options, _ => options.MaxRequestBodySize = 1024 * 1024 * Global.MaxRequestBodySize));
		}

		public void Configure(IApplicationBuilder appBuilder, IHostApplicationLifetime appLifetime, IWebHostEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Console.OutputEncoding = Encoding.UTF8;
			Global.ServiceName = "APIGateway";
			AspNetCoreUtilityService.ServerName = UtilityService.GetAppSetting("ServerName", "VIEApps NGX");
			Components.WebSockets.WebSocket.AgentName = $"{AspNetCoreUtilityService.ServerName} WebSockets";

			var loggerFactory = appBuilder.ApplicationServices.GetService<ILoggerFactory>();
			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if ("true".IsEquals(UtilityService.GetAppSetting("Logs:WriteFiles", "true")) && !string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}" + $"_{Global.ServiceName.ToLower()}.http.txt");
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
			Global.Logger.LogInformation($"Environment:\r\n\t{Extensions.GetRuntimeEnvironment()}");
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

			// prepare outgoing proxy
			var proxy = UtilityService.GetAppSetting("Proxy:Host");
			if (!string.IsNullOrWhiteSpace(proxy))
				try
				{
					UtilityService.AssignWebProxy(proxy, UtilityService.GetAppSetting("Proxy:Port").CastAs<int>(), UtilityService.GetAppSetting("Proxy:User"), UtilityService.GetAppSetting("Proxy:UserPassword"), UtilityService.GetAppSetting("Proxy:Bypass")?.ToArray(";"));
				}
				catch (Exception ex)
				{
					Global.Logger.LogError($"Error occurred while assigning web-proxy => {ex.Message}", ex);
				}

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
					KeepAliveInterval = RTU.WebSocket.KeepAliveInterval
				});

			// setup the forwarder of API Gateway Router
			var enableForwarder = "true".IsEquals(UtilityService.GetAppSetting("Router:Forwarder", "false"));
			if (enableForwarder)
				appBuilder.Map("/router", builder => Router.OpenForwarder(builder));

			// setup the path mappers
			var onIncomingConnectionEstablished = new List<Action<object, WampSessionCreatedEventArgs>>();
			var onOutgoingConnectionEstablished = new List<Action<object, WampSessionCreatedEventArgs>>();
			if (System.Configuration.ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Maps", "net.vieapps.services.apigateway.http.maps")) is AppConfigurationSectionHandler config && config.Section.SelectNodes("map") is System.Xml.XmlNodeList maps)
				maps.ToList()
					.Select(info => new Tuple<string, string>(info.Attributes["path"]?.Value?.ToLower()?.Trim(), info.Attributes["type"]?.Value))
					.Where(info => !string.IsNullOrEmpty(info.Item1) && !string.IsNullOrEmpty(info.Item2))
					.Select(info =>
					{
						var path = info.Item1;
						while (path.StartsWith("/"))
							path = path.Right(path.Length - 1);
						while (path.EndsWith("/"))
							path = path.Left(path.Length - 1);
						return new Tuple<string, string>(path, info.Item2);
					})
					.Where(info => !info.Item1.IsEquals("router"))
					.ForEach(info =>
					{
						try
						{
							if (AssemblyLoader.GetType(info.Item2)?.CreateInstance() is PathMapper mapper)
							{
								appBuilder.Map($"/{info.Item1}", builder => mapper.Map(builder, appLifetime, onIncomingConnectionEstablished, onOutgoingConnectionEstablished));
								Global.Logger.LogInformation($"Successfully branch the request to a specified path: /{info.Item1} => {mapper.GetTypeName()}");
							}
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Cannot load a path mapper ({info.Item2}) => {ex.Message}", ex);
						}
					});

			// setup the handler for all requests
			appBuilder.UseMiddleware<Handler>();

			// setup the caching storage
			Global.Cache = appBuilder.ApplicationServices.GetService<ICache>();

			// connect to API Gateway Router
			Router.Connect(onIncomingConnectionEstablished, onOutgoingConnectionEstablished);

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
				Global.Logger.LogInformation($"Status files directory: {UtilityService.GetAppSetting("Path:Status", "None")}");
				Global.Logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:Statics", "None")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Logging level: {this.LogLevel} - Local rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");
				Global.Logger.LogInformation($"Request body limit: {Global.MaxRequestBodySize:###,###,##0} MB");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service was started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// assign app event handler => on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();
				RTU.Dispose();
				Global.RSA.Dispose();
				if (enableForwarder)
					Router.CloseForwarder();
			});

			// assign app event handler => on stopped
			appLifetime.ApplicationStopped.Register(() =>
			{
				Router.Disconnect();
				Global.CancellationTokenSource.Cancel();
				Global.CancellationTokenSource.Dispose();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service was stopped");
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