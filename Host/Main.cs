﻿#region Related components
using System;
using System.IO;
using System.Linq;
using System.Xml;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
    public class HostingComponent
    {
		IServiceComponent ServiceComponent { get; set; }

		ILogger Logger { get; set; }

		public void Start(string[] args)
		{
			// prepare
			var stopwatch = Stopwatch.StartNew();
			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var apiCallToStop = apiCall != null && apiCall.IsEquals("/agc:s");
			var isUserInteractive = Environment.UserInteractive && apiCall == null;
			if (isUserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

			// prepare type name
			var typeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			var configFilename = $"VIEApps.Services.APIGateway.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "exe" : "dll")}.config";
			if (string.IsNullOrWhiteSpace(typeName) && File.Exists(configFilename) && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
				try
				{
					var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
					var xml = new XmlDocument();
					xml.LoadXml(UtilityService.ReadTextFile(configFilename));
					typeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "").Replace(StringComparison.OrdinalIgnoreCase, ",x86", "");
				}
				catch { }

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(typeName))
			{
				if (isUserInteractive)
				{
					Console.WriteLine($"VIEApps NGX API Gateway - Service Hosting v{typeof(HostingComponent).Assembly.GetVersion()}");
					Console.WriteLine("");
					Console.WriteLine("Syntax: VIEApps.Services.APIGateway.Hosting /svc:<service-component-namespace,service-assembly>");
					Console.WriteLine("");
					Console.WriteLine("Ex.: VIEApps.Services.APIGateway.Hosting /svc:net.vieapps.Services.Systems.ServiceComponent,VIEApps.Services.Systems");
					Console.WriteLine("");
					Console.ReadLine();
				}
				else
					Console.WriteLine("No matched type name is found");
				return;
			}

			// initialize the instance of service component
			var serviceType = Type.GetType(typeName);
			if (serviceType == null)
			{
				Console.WriteLine($"The type of the service component is not found [{typeName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			this.ServiceComponent = serviceType.CreateInstance() as IServiceComponent;
			if (this.ServiceComponent == null || !(this.ServiceComponent is IService))
			{
				Console.WriteLine($"The type of the service component is invalid [{typeName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare the signal to start/stop when the service was called from API Gateway
			EventWaitHandle waitHandle = null;
			if (!isUserInteractive)
			{
				// get the flag of the existing instance
				waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, (this.ServiceComponent as IService).ServiceURI, out bool createdNew);

				// process the call to stop
				if (apiCallToStop)
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						waitHandle.Set();

					// then exit
					waitHandle.Dispose();
					this.ServiceComponent.Dispose();
					return;
				}
			}

			// prepare default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Newtonsoft.Json.Formatting.Indented,
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

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>());

			var path = UtilityService.GetAppSetting("Path:Logs");
			if (Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}_" + (this.ServiceComponent as IService).ServiceName.ToLower() + ".txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(path, logLevel);
			}
			else
				path = null;

			if (isUserInteractive)
				Components.Utility.Logger.GetLoggerFactory().AddConsole(logLevel);

			this.Logger = this.ServiceComponent.Logger = Components.Utility.Logger.CreateLogger(serviceType);

			// start the service component
			this.Logger.LogInformation($"The service is starting");
			this.Logger.LogInformation($"Version: {serviceType.Assembly.GetVersion()}");
			this.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? $"Windows {RuntimeInformation.OSArchitecture}" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? $"Linux {RuntimeInformation.OSArchitecture}" : $"Other {RuntimeInformation.OSArchitecture} OS")} ({RuntimeInformation.OSDescription.Trim()})");
			this.ServiceComponent.Start(
				args,
				"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true,
				service =>
				{
					this.Logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterInfo().Item1}");
					this.Logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
					this.Logger.LogInformation($"Default logging level: {logLevel}");
					if (!string.IsNullOrWhiteSpace(path))
						this.Logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
					stopwatch.Stop();
					this.Logger.LogInformation($"The service is started - PID: {Process.GetCurrentProcess().Id} - URI: {service.ServiceURI} - Execution times: {stopwatch.GetElapsedTimes()}");
					this.Logger.LogWarning($"=====> Press RETURN to terminate...............");
					return Task.CompletedTask;
				}
			);

			// assign the static instance of the service component
			ServiceBase.ServiceComponent = this.ServiceComponent as ServiceBase;

			// wait for exit signal
			if (isUserInteractive)
			{
				Console.ReadLine();
				this.Stop();
			}
			else
			{
				waitHandle.WaitOne();
				waitHandle.Dispose();
				this.Stop();
			}
		}

		public void Stop()
		{
			this.ServiceComponent?.Dispose();
			this.Logger.LogInformation($"The service is stopped");
		}
	}
}