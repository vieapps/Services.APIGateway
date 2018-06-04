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
			var start = DateTime.Now;
			var stopwatch = Stopwatch.StartNew();

			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var isUserInteractive = Environment.UserInteractive && apiCall == null;

			// prepare type name
			var serviceTypeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			if (string.IsNullOrWhiteSpace(serviceTypeName) && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
			{
				var configFilename = $"{UtilityService.GetAppSetting("Path:APIGateway", "")}VIEApps.Services.APIGateway.{(RuntimeInformation.FrameworkDescription.IsContains(".NET Framework") ? "exe" : "dll")}.config";
				if (File.Exists(configFilename))
					try
					{
						var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
						var xml = new System.Xml.XmlDocument();
						xml.LoadXml(UtilityService.ReadTextFile(configFilename));
						serviceTypeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "");
					}
					catch { }
			}

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(serviceTypeName))
			{
				if (isUserInteractive)
				{
					Console.Error.WriteLine($"VIEApps NGX API Gateway - Service Hosting v{Assembly.GetExecutingAssembly().GetVersion()}" + "\r\n");
					Console.Error.WriteLine("Syntax: VIEApps.Services.APIGateway /svc:<service-component-namespace,service-assembly>" + "\r\n");
					Console.Error.WriteLine("Ex.: VIEApps.Services.APIGateway /svc:net.vieapps.Services.Systems.ServiceComponent,VIEApps.Services.Systems" + "\r\n");
					Console.ReadLine();
				}
				else
					Console.Error.WriteLine("Service type name is invalid");
				return;
			}

			// prepare type of the service component
			Type serviceType = null;
			try
			{
				serviceType = Type.GetType(serviceTypeName);
				if (serviceType == null)
				{
					Console.Error.WriteLine($"The type of the service component is not found [{serviceTypeName}]");
					if (isUserInteractive)
						Console.ReadLine();
					return;
				}
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine($"Error occurred while prepare the type of the service component [{serviceTypeName}] => {ex.Message}");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// initialize the instance of service component
			if (!(serviceType.CreateInstance() is IServiceComponent serviceComponent) || !(serviceComponent is ServiceBase))
			{
				Console.Error.WriteLine($"The type of the service component is invalid [{serviceTypeName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare the signal to start/stop when the service was called from API Gateway
			EventWaitHandle eventWaitHandle = null;
			var useEventWaitHandle = !isUserInteractive && RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			if (useEventWaitHandle)
			{
				// get the flag of the existing instance
				var name = $"{serviceComponent.ServiceURI}#{string.Join("#", (args ?? new string[] { }).Where(a => !a.IsStartsWith("/agc:"))).GenerateUUID()}";
				eventWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, name, out bool createdNew);

				// process the call to stop
				if ("/agc:s".IsEquals(apiCall))
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						eventWaitHandle.Set();

					// then exit
					eventWaitHandle.Dispose();
					serviceComponent.Dispose();
					return;
				}
			}

			// prepare environment
			Console.OutputEncoding = System.Text.Encoding.UTF8;
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
			logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");

			ServiceBase.ServiceComponent = serviceComponent as ServiceBase;
			serviceComponent.Start(
				args,
				"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true,
				service =>
				{
					logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterStrInfo()}");
					logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
					logger.LogInformation($"Default logging level: {logLevel}");
					if (!string.IsNullOrWhiteSpace(path))
						logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
					logger.LogInformation($"Show debugs: {(service as ServiceBase).IsDebugLogEnabled} - Show results: {(service as ServiceBase).IsDebugResultsEnabled} - Show stacks: {(service as ServiceBase).IsDebugStacksEnabled}");

					stopwatch.Stop();
					logger.LogInformation($"The service is started - PID: {Process.GetCurrentProcess().Id} - URI: {service.ServiceURI} - Execution times: {stopwatch.GetElapsedTimes()}");

					if (isUserInteractive)
						logger.LogWarning($"=====> Enter \"exit\" to terminate ...............");

					return Task.CompletedTask;
				}
			);

			// wait for exit signal
			if (useEventWaitHandle)
			{
				eventWaitHandle.WaitOne();
				eventWaitHandle.Dispose();
				logger.LogDebug(">>>>> Got \"stop\" call from API Gateway ...............");
			}
			else
			{
				while (Console.ReadLine() != "exit") { }
				if (!isUserInteractive)
					logger.LogDebug(">>>>> Got \"exit\" command from API Gateway ...............");
			}

			serviceComponent.Stop();
			serviceComponent.Dispose();

			logger.LogInformation($"The service is stopped - Served times: {start.GetElapsedTimes()}");
		}
	}
}