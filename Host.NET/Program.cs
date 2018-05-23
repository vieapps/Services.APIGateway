#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			var stopwatch = Stopwatch.StartNew();

			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var isUserInteractive = Environment.UserInteractive && apiCall == null;

			// prepare type name
			var typeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			var configFilename = $"VIEApps.Services.APIGateway.{(RuntimeInformation.FrameworkDescription.IsContains(".NET Framework") ? "exe" : "dll")}.config";
			if (string.IsNullOrWhiteSpace(typeName) && File.Exists(configFilename) && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
				try
				{
					var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
					var xml = new System.Xml.XmlDocument();
					xml.LoadXml(UtilityService.ReadTextFile(configFilename));
					typeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "").Replace(StringComparison.OrdinalIgnoreCase, ",x86", "");
				}
				catch { }

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(typeName))
			{
				if (isUserInteractive)
				{
					Console.WriteLine($"VIEApps NGX API Gateway - Service Hosting v{Assembly.GetExecutingAssembly().GetVersion()}");
					Console.WriteLine("");
					Console.WriteLine("Syntax: VIEApps.Services.Hosting /svc:<service-component-namespace,service-assembly>");
					Console.WriteLine("");
					Console.WriteLine("Ex.: VIEApps.Services.Hosting /svc:net.vieapps.Services.Systems.ServiceComponent,VIEApps.Services.Systems");
					Console.WriteLine("");
					Console.ReadLine();
				}
				else
					Console.WriteLine("Type name is invalid");
				return;
			}

			// prepare type of the service component
			Type serviceType = null;
			try
			{
				serviceType = Type.GetType(typeName);
				if (serviceType == null)
				{
					Console.WriteLine($"The type of the service component is not found [{typeName}]");
					if (isUserInteractive)
						Console.ReadLine();
					return;
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error occurred while prepare the type of the service component [{typeName}] => {ex.Message}");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// initialize the instance of service component
			if (!(serviceType.CreateInstance() is IServiceComponent serviceComponent) || !(serviceComponent is IService))
			{
				Console.WriteLine($"The type of the service component is invalid [{typeName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare the signal to start/stop when the service was called from API Gateway
			var canUseWaitHandler = !isUserInteractive && RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			EventWaitHandle waitHandle = null;
			if (canUseWaitHandler)
			{
				// get the flag of the existing instance
				waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, serviceComponent.ServiceURI, out bool createdNew);

				// process the call to stop
				if ("/agc:s".IsEquals(apiCall))
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						waitHandle.Set();

					// then exit
					waitHandle.Dispose();
					serviceComponent.Dispose();
					return;
				}
			}

			// prepare default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare logging
#if DEBUG
			var logLevel = LogLevel.Debug;
#else
			var logLevel = LogLevel.Information;
			try
			{
				logLevel = UtilityService.GetAppSetting("Logs:Level", "Information").ToEnum<LogLevel>();
			}
			catch { }
#endif

			Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>());

			var path = UtilityService.GetAppSetting("Path:Logs");
			if (Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}_" + serviceComponent.ServiceName.ToLower() + ".txt");
				Logger.GetLoggerFactory().AddFile(path, logLevel);
			}
			else
				path = null;

			if (isUserInteractive)
				Logger.GetLoggerFactory().AddConsole(logLevel);

			var logger = serviceComponent.Logger = Logger.CreateLogger(serviceType);

			// start the service component
			logger.LogInformation($"The service is starting");
			logger.LogInformation($"Version: {serviceType.Assembly.GetVersion()}");
			logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "Other OS")} {RuntimeInformation.OSArchitecture} ({RuntimeInformation.OSDescription.Trim()})");

			ServiceBase.ServiceComponent = serviceComponent as ServiceBase;
			serviceComponent.Start(
				args,
				"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true,
				service =>
				{
					logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterInfo().Item1}");
					logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
					logger.LogInformation($"Default logging level: {logLevel}");
					if (!string.IsNullOrWhiteSpace(path))
						logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
					stopwatch.Stop();
					logger.LogInformation($"The service is started - PID: {Process.GetCurrentProcess().Id} - URI: {service.ServiceURI} - Execution times: {stopwatch.GetElapsedTimes()}");
					if (isUserInteractive)
						logger.LogWarning($"=====> Type 'exit' to terminate ...............");
					return Task.CompletedTask;
				}
			);

			// wait for exit signal
			if (canUseWaitHandler)
			{
				waitHandle.WaitOne();
				waitHandle.Dispose();
			}
			else
			{
				while (Console.ReadLine() != "exit") { }
				if (!isUserInteractive && logger.IsEnabled(LogLevel.Debug))
					logger.LogInformation($"++>> Got 'exit' command input from API Gateway ...............");
			}

			serviceComponent.Stop();
			serviceComponent.Dispose();

			logger.LogInformation($"The service is stopped");
		}
	}
}