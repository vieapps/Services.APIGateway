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
using net.vieapps.Components.Repository;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Startup(IConfiguration configuration)
	{
		public static void Main(string[] args)
			=> WebHost.CreateDefaultBuilder(args).Run<Startup>(args);

		public IConfiguration Configuration { get; } = configuration;

		public LogLevel LogLevel => this.Configuration.GetAppSetting("Logging/LogLevel/Default", UtilityService.GetAppSetting("Logs:Level", "Information")).TryToEnum(out LogLevel logLevel) ? logLevel : LogLevel.Information;

		public void ConfigureServices(IServiceCollection services)
		{
			services
				.AddHttpContextAccessor()
				.AddResponseCompression(options => Global.PrepareResponseCompression(options))
				.AddLogging(builder => builder.SetMinimumLevel(this.LogLevel))
				.AddCache(options => this.Configuration.GetSection("Cache").Bind(options));
			if (Global.UseIISInProcess)
				services.Configure<IISServerOptions>(options => Global.PrepareIISServerOptions(options, _ => options.MaxRequestBodySize = 1024 * 1024 * Global.MaxRequestBodySize));
		}

		public void Configure(IApplicationBuilder appBuilder, IHostApplicationLifetime appLifetime, IWebHostEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Console.OutputEncoding = Encoding.UTF8;
			Global.ServiceName = "APIGateway";

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
			RESTfulAPIs.Logger = loggerFactory.CreateLogger<Handler.RESTfulAPIs>();
			WebSocketAPIs.Logger = loggerFactory.CreateLogger<Handler.WebSocketAPIs>();

			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");
			Global.Logger.LogInformation($"Version: {typeof(Startup).Assembly.GetVersion()}");
#if DEBUG
			Global.Logger.LogInformation($"Working mode: DEBUG ({(environment.IsDevelopment() ? "Development" : "Production")})");
#else
			Global.Logger.LogInformation($"Working mode: RELEASE ({(environment.IsDevelopment() ? "Development" : "Production")})");
#endif
			Global.Logger.LogInformation($"Service URIs:\r\n\t- Round robin: services.{Global.ServiceName.ToLower()}.http\r\n\t- Single (unique): services.{Extensions.GetUniqueName($"{Global.ServiceName}.http")}");
			Global.Logger.LogInformation($"Environment:\r\n\t{Extensions.GetRuntimeEnvironment()}\r\n\t- Node ID: {Extensions.GetNodeID()}");

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
					UtilityService.AssignWebProxy(proxy, UtilityService.GetAppSetting("Proxy:Port").As<int>(), UtilityService.GetAppSetting("Proxy:User"), UtilityService.GetAppSetting("Proxy:UserPassword"), UtilityService.GetAppSetting("Proxy:Bypass")?.ToArray(";"));
				}
				catch (Exception ex)
				{
					Global.Logger.LogError($"Error occurred while assigning web-proxy => {ex.Message}", ex);
				}

			// setup the real-time updater
			WebSocketAPIs.Initialize();

			// setup the middlewares
			appBuilder
				.UseForwardedHeaders(Global.GetForwardedHeadersOptions())
				.UseCache()
				.UseStatusCodeHandler()
				.UseResponseCompression()
				.UseWebSockets(new WebSocketOptions
				{
					KeepAliveInterval = WebSocketAPIs.KeepAliveInterval
				});

			// setup the forwarder of API Gateway Router
			var enableForwarder = "true".IsEquals(UtilityService.GetAppSetting("Router:Forwarder", "false"));
			if (enableForwarder)
				appBuilder.Map("/router", _ => Router.OpenForwarder(appBuilder));

			// setup the path mappers
			var onIncomingConnectionEstablished = new List<Action<object, WampSessionCreatedEventArgs>>();
			var onOutgoingConnectionEstablished = new List<Action<object, WampSessionCreatedEventArgs>>();
			var pathMappers = new List<string>();
			if (System.Configuration.ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Maps", "net.vieapps.services.apigateway.http.maps")) is AppConfigurationSectionHandler cfgMaps && cfgMaps.Section.SelectNodes("map") is System.Xml.XmlNodeList maps)
				maps.ToList()
				.Select(info => (Path: info.Attributes["path"]?.Value?.ToLower()?.Trim(), Type: info.Attributes["type"]?.Value))
				.Where(info => !string.IsNullOrEmpty(info.Path) && !string.IsNullOrEmpty(info.Type))
				.Select(info =>
				{
					var path = info.Path;
					while (path.StartsWith('/'))
						path = path.Right(path.Length - 1);
					while (path.EndsWith('/'))
						path = path.Left(path.Length - 1);
					return (Path: path, info.Type);
				})
				.Where(info => !info.Path.IsEquals("router"))
				.ForEach(info =>
				{
					try
					{
						if (AssemblyLoader.GetType(info.Type)?.CreateInstance() is PathMapper mapper)
						{
							appBuilder.Map($"/{info.Path}", builder => mapper.Map(builder, appLifetime, onIncomingConnectionEstablished, onOutgoingConnectionEstablished));
							Global.Logger.LogInformation($"Successfully branch the request to a specified path: /{info.Path} => {mapper.GetTypeName()}");
							pathMappers.Add($"/{info.Path} => {mapper.GetTypeName()}");
						}
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Cannot load a path mapper ({info.Type}) => {ex.Message}", ex);
					}
				});

			// setup the handler for all requests
			appBuilder.UseMiddleware<Handler>();

			// connect to API Gateway Router
			Router.Connect(onIncomingConnectionEstablished, onOutgoingConnectionEstablished);

			// setup the service forwarders
			if (System.Configuration.ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Forwarders", "net.vieapps.services.apigateway.http.forwarders")) is AppConfigurationSectionHandler cfgForwarders && cfgForwarders.Section.SelectNodes("forwarder") is System.Xml.XmlNodeList forwarders)
				forwarders.ToList()
				.Select(info => (Name: info.Attributes["name"]?.Value?.ToLower()?.Trim(), Type: info.Attributes["type"]?.Value, EndpointURL: info.Attributes["endpointURL"]?.Value, DataSource: info.Attributes["dataSource"]?.Value))
				.Where(info => !string.IsNullOrEmpty(info.Name) && !string.IsNullOrEmpty(info.Type) && !string.IsNullOrEmpty(info.Type))
				.Select(info => (Name: info.Name.GetANSIUri(), info.Type, info.EndpointURL, info.DataSource))
				.Where(info => !info.Name.IsEquals("router") && !info.Name.IsEquals("pusher"))
				.ForEach(info =>
				{
					try
					{
						var type = AssemblyLoader.GetType(info.Type);
						if (type != null && type.CreateInstance() is ServiceForwarder)
							RESTfulAPIs.ServiceForwarders[info.Name] = (type, info.EndpointURL, info.DataSource);
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Cannot load a service forwarder ({info.Type}) => {ex.Message}", ex);
					}
				});

			// construct data-sources and connection strings
			if (!RESTfulAPIs.ServiceForwarders.IsEmpty)
			{
				var dbProviderFactories = new Dictionary<string, System.Xml.XmlNode>(StringComparer.OrdinalIgnoreCase);
				var dbprovidersSection = UtilityService.GetAppSetting("Section:DbProviders", "net.vieapps.dbproviders");
				if (System.Configuration.ConfigurationManager.GetSection(dbprovidersSection) is not AppConfigurationSectionHandler dbProvidersConfiguration)
					dbProvidersConfiguration = System.Configuration.ConfigurationManager.GetSection("dbProviderFactories") as AppConfigurationSectionHandler;
				dbProvidersConfiguration?.Section.SelectNodes("./add").ToList().ForEach(dbProviderNode =>
				{
					var invariant = dbProviderNode.Attributes["invariant"]?.Value ?? dbProviderNode.Attributes["name"]?.Value;
					if (!string.IsNullOrWhiteSpace(invariant) && !dbProviderFactories.ContainsKey(invariant))
						dbProviderFactories[invariant] = dbProviderNode;
				});
				RepositoryStarter.ConstructDbProviderFactories(dbProviderFactories.Values.ToList(), (msg, ex) =>
				{
					if (ex != null)
						Global.Logger.LogError(msg, ex);
					else
						Global.Logger.LogInformation(msg);
				});

				var connectionStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
				if (System.Configuration.ConfigurationManager.ConnectionStrings != null && System.Configuration.ConfigurationManager.ConnectionStrings.Count > 0)
					for (var index = 0; index < System.Configuration.ConfigurationManager.ConnectionStrings.Count; index++)
					{
						var connectionString = System.Configuration.ConfigurationManager.ConnectionStrings[index];
						if (!connectionStrings.ContainsKey(connectionString.Name))
							connectionStrings[connectionString.Name] = connectionString.ConnectionString;
					}

				var dataSourcesSection = UtilityService.GetAppSetting("Section:DataSources", "net.vieapps.data.sources");
				var dataSources = new Dictionary<string, System.Xml.XmlNode>(StringComparer.OrdinalIgnoreCase);
				if (System.Configuration.ConfigurationManager.GetSection(dataSourcesSection) is AppConfigurationSectionHandler dataSourcesConfiguration)
					dataSourcesConfiguration.Section.SelectNodes("./add").ToList().ForEach(dataSourceNode =>
					{
						var dataSourceName = dataSourceNode.Attributes["name"]?.Value;
						if (!string.IsNullOrWhiteSpace(dataSourceName) && !dataSources.ContainsKey(dataSourceName))
						{
							var connectionStringName = dataSourceNode.Attributes["connectionStringName"]?.Value;
							if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.TryGetValue(connectionStringName, out var connectionString))
							{
								var attribute = dataSourceNode.OwnerDocument.CreateAttribute("connectionString");
								attribute.Value = connectionString;
								dataSourceNode.Attributes.Append(attribute);
								dataSources[dataSourceName] = dataSourceNode;
							}
						}
					});
				RepositoryStarter.ConstructDataSources(dataSources.Values.ToList(), (msg, ex) =>
				{
					if (ex != null)
						Global.Logger.LogError(msg, ex);
					else
						Global.Logger.LogInformation(msg);
				});
			}

			// assign app event handler => on started
			appLifetime.ApplicationStarted.Register(() =>
			{
				Global.Logger.LogInformation($"API Gateway Router: {new Uri(Services.Router.GetRouterStrInfo()).GetResolvedURI()}");
				if (enableForwarder)
					Global.Logger.LogInformation($"Forwarder of API Gateway Router: {UtilityService.GetAppSetting("HttpUri:APIs")}/router");

				Global.Logger.LogInformation($"API Gateway HTTP service: {UtilityService.GetAppSetting("HttpUri:APIs", "None")}");
				Global.Logger.LogInformation($"Files HTTP service: {UtilityService.GetAppSetting("HttpUri:Files", "None")}");
				Global.Logger.LogInformation($"Portals HTTP service: {UtilityService.GetAppSetting("HttpUri:Portals", "None")}");
				Global.Logger.LogInformation($"Root (base) directory: {Global.RootPath}");
				Global.Logger.LogInformation($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
				Global.Logger.LogInformation($"Status files directory: {UtilityService.GetAppSetting("Path:Status", "None")}");
				Global.Logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:Statics", "None")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Logging level: {this.LogLevel} - Local rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");
				Global.Logger.LogInformation($"Request body limit: {Global.MaxRequestBodySize:###,###,##0} MB");

				Global.Logger.LogInformation($"Path mappers: {(pathMappers.Count > 0 ? "\r\n\t" + pathMappers.ToString("\r\n\t") : "None")}");
				Global.Logger.LogInformation($"Service forwarders: {(RESTfulAPIs.ServiceForwarders.IsEmpty ? "None" : "\r\n\t" + RESTfulAPIs.ServiceForwarders.ToString("\r\n\t", kvp => $"/{kvp.Key} => {kvp.Value.EndpointURL} [{kvp.Value.Type.GetTypeName()}]"))}");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service was started - PID: {Environment.ProcessId} - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// assign app event handler => on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();
				Global.RSA.Dispose();
				WebSocketAPIs.Dispose();
				if (enableForwarder)
					Router.CloseForwarder();
				Router.Disconnect();
			});

			// assign app event handler => on stopped
			appLifetime.ApplicationStopped.Register(() =>
			{
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