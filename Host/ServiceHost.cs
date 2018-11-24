﻿#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public abstract class ServiceHost
	{
		protected string ServiceTypeName { get; private set; }
		protected string ServiceAssemblyName { get; private set; }
		protected Type ServiceType { get; set; }

		public void Run(string[] args)
		{
			// prepare
			var start = DateTime.Now;
			var stopwatch = Stopwatch.StartNew();

			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var isUserInteractive = Environment.UserInteractive && apiCall == null;

			// prepare type name
			this.ServiceTypeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			if (string.IsNullOrWhiteSpace(this.ServiceTypeName) && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
			{
				var configFilename = $"{UtilityService.GetAppSetting("Path:APIGateway", "")}VIEApps.Services.APIGateway.{(RuntimeInformation.FrameworkDescription.IsContains(".NET Framework") ? "exe" : "dll")}.config";
				if (File.Exists(configFilename))
					try
					{
						var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
						var xml = new System.Xml.XmlDocument();
						xml.LoadXml(UtilityService.ReadTextFile(configFilename));
						this.ServiceTypeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "");
					}
					catch { }
			}

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(this.ServiceTypeName))
			{
				Console.Error.WriteLine($"VIEApps NGX API Gateway - Service Hosting v{typeof(ServiceHost).Assembly.GetVersion()}" + "\r\n");
				Console.Error.WriteLine("");
				Console.Error.WriteLine("Error: The service type name is invalid");
				Console.Error.WriteLine("");
				Console.Error.WriteLine("Syntax: VIEApps.Services.APIGateway /svc:<service-component-namespace,service-assembly>" + "\r\n");
				Console.Error.WriteLine("Ex.: VIEApps.Services.APIGateway /svc:net.vieapps.Services.Portals.ServiceComponent,VIEApps.Services.Portals" + "\r\n");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare type name & assembly name of the service component
			var serviceInfo = this.ServiceTypeName.ToArray();
			this.ServiceTypeName = serviceInfo[0];
			this.ServiceAssemblyName = serviceInfo.Length > 1 ? serviceInfo[1] : "Unknown";

			// prepare the type of the service component
			try
			{
				this.PrepareServiceType();
				if (this.ServiceType == null)
				{
					Console.Error.WriteLine($"The type of the service component is not found [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
					if (isUserInteractive)
						Console.ReadLine();
					return;
				}
			}
			catch (Exception ex)
			{
				if (ex is ReflectionTypeLoadException)
				{
					Console.Error.WriteLine($"Error occurred while preparing the type of the service component [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
					(ex as ReflectionTypeLoadException).LoaderExceptions.ForEach(exception =>
					{
						Console.Error.WriteLine($"{exception.Message}");
						var inner = exception.InnerException;
						while (inner != null)
						{
							Console.Error.WriteLine($"{inner.Message} [{inner.GetType()}]\r\nStack: {inner.StackTrace}");
							inner = inner.InnerException;
						}
					});
				}
				else
				{
					Console.Error.WriteLine($"Error occurred while preparing the type of the service component [{this.ServiceTypeName},{this.ServiceAssemblyName}] => {ex.Message}");
					var inner = ex.InnerException;
					while (inner != null)
					{
						Console.Error.WriteLine($"{inner.Message}\r\nStack: {inner.StackTrace}");
						inner = inner.InnerException;
					}
				}
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// check the type of the service component
			if (!typeof(IServiceComponent).IsAssignableFrom(this.ServiceType) || !typeof(ServiceBase).IsAssignableFrom(this.ServiceType))
			{
				Console.Error.WriteLine($"The type of the service component is invalid [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// initialize the instance of service component
			var serviceComponent = this.ServiceType.CreateInstance() as IServiceComponent;

			// prepare the signal to start/stop when the service was called from API Gateway
			EventWaitHandle eventWaitHandle = null;
			var useEventWaitHandle = !isUserInteractive && RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			if (useEventWaitHandle)
			{
				// get the flag of the existing instance
				var name = $"{serviceComponent.ServiceURI}#{string.Join("#", args.Where(a => !a.IsStartsWith("/agc:"))).GenerateUUID()}";
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
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
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

			var logger = serviceComponent.Logger = Logger.CreateLogger(this.ServiceType);

			// setup hooks
			bool stopped = false;
			void stop()
			{
				stopped = true;
				serviceComponent.Stop();
				serviceComponent.Dispose();
			}

			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) =>
			{
				if (!stopped)
				{
					stop();
					logger.LogInformation($"The service is stopped (by \"process exit\" signal) - Served times: {start.GetElapsedTimes()}");
				}
			};

			Console.CancelKeyPress += (sender, arguments) =>
			{
				if (!stopped)
				{
					stop();
					logger.LogInformation($"The service is stopped (by \"cancel key press\" signal) - Served times: {start.GetElapsedTimes()}");
				}
				Environment.Exit(0);
			};

			// start the service component
			logger.LogInformation($"The service is starting");
			logger.LogInformation($"Mode: {(isUserInteractive ? "Interactive app" : "Background service")}");
			logger.LogInformation($"Version: {this.ServiceType.Assembly.GetVersion()}");
			logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");

			ServiceBase.ServiceComponent = serviceComponent as ServiceBase;
			serviceComponent.Start(
				args,
				"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true,
				service =>
				{
					logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterStrInfo()}");
					logger.LogInformation($"Base path: {AppContext.BaseDirectory}");
					logger.LogInformation($"Logs path: {UtilityService.GetAppSetting("Path:Logs")}");
					logger.LogInformation($"Default logging level: {logLevel}");
					if (!string.IsNullOrWhiteSpace(path))
						logger.LogInformation($"Rolling log files is enabled - Path format: {path}");
					logger.LogInformation($"Show debugs: {(service as ServiceBase).IsDebugLogEnabled} - Show results: {(service as ServiceBase).IsDebugResultsEnabled} - Show stacks: {(service as ServiceBase).IsDebugStacksEnabled}");

					stopwatch.Stop();
					logger.LogInformation($"Service URI (round robin): {service.ServiceURI}");
					logger.LogInformation($"Service URI (single): {(service as IUniqueService).ServiceUniqueURI}");
					logger.LogInformation($"The service is started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");

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

			stop();
			logger.LogInformation($"The service is stopped - Served times: {start.GetElapsedTimes()}");
		}

		protected virtual void PrepareServiceType() => this.ServiceType = Type.GetType($"{this.ServiceTypeName},{this.ServiceAssemblyName}");
	}
}