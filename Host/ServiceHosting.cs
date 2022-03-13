using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services.APIGateway
{
	public abstract class ServiceHostingBase
	{
		protected string ServiceTypeName { get; private set; }

		protected string ServiceAssemblyName { get; private set; }

		protected Type ServiceType { get; set; }

		protected virtual void PrepareServiceType()
			=> this.ServiceType = Type.GetType($"{this.ServiceTypeName},{this.ServiceAssemblyName}");

		public void Run(string[] args = null)
		{
			try
			{
				this.Run(args?.ToList());
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine($"Error: The service component was got an unexpected error => {ex.Message}\r\n{ex.StackTrace}");
			}
		}

		void Run(List<string> args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			var time = DateTime.Now;
			var stopwatch = Stopwatch.StartNew();

			var apiCall = args?.FirstOrDefault(arg => arg.IsStartsWith("/agc:"));
			var isUserInteractive = Environment.UserInteractive && apiCall == null;
			var doSyncWork = args?.FirstOrDefault(arg => arg.IsStartsWith("/do-sync-work")) != null;
			var startBeforeDoingSyncWork = doSyncWork && args?.FirstOrDefault(arg => arg.IsStartsWith("/start-before-sync-work")) != null;
			var powered = $"VIEApps NGX API Gateway - Service Hosting {RuntimeInformation.ProcessArchitecture.ToString().ToLower()} {Assembly.GetCallingAssembly().GetVersion()}";

			// prepare type name
			this.ServiceTypeName = args?.FirstOrDefault(arg => arg.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			if (string.IsNullOrWhiteSpace(this.ServiceTypeName) && args?.FirstOrDefault(arg => arg.IsStartsWith("/svn:")) != null)
			{
				var configFilePath = Path.Combine($"{UtilityService.GetAppSetting("Path:APIGateway:Controller")}", $"VIEApps.Services.APIGateway.{(RuntimeInformation.FrameworkDescription.IsContains(".NET Framework") ? "exe" : "dll")}.config");
				if (File.Exists(configFilePath))
					try
					{
						var xml = new System.Xml.XmlDocument();
						xml.LoadXml(new FileInfo(configFilePath).ReadAsText());
						this.ServiceTypeName = args.First(arg => arg.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").Trim();
						var typeNode = xml.SelectSingleNode($"/configuration/{UtilityService.GetAppSetting("Section:Services", "net.vieapps.services")}")?.ChildNodes?.ToList()?.FirstOrDefault(node => this.ServiceTypeName.IsEquals(node.Attributes["name"]?.Value));
						this.ServiceTypeName = typeNode?.Attributes["type"]?.Value;
					}
					catch
					{
						this.ServiceTypeName = null;
					}
			}

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(this.ServiceTypeName))
			{
				Console.Error.WriteLine(powered);
				Console.Error.WriteLine("");
				Console.Error.WriteLine("Error: The service component is invalid (no type name)");
				Console.Error.WriteLine("");
				Console.Error.WriteLine("Syntax: VIEApps.Services.APIGateway /svc:<service-component-namespace,service-assembly>");
				Console.Error.WriteLine("");
				Console.Error.WriteLine("Ex.: VIEApps.Services.APIGateway /svc:net.vieapps.Services.Users.ServiceComponent,VIEApps.Services.Users");
				Console.Error.WriteLine("");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// prepare type name & assembly name of the service component
			var serviceTypeInfo = this.ServiceTypeName.ToArray();
			this.ServiceTypeName = serviceTypeInfo.First();
			this.ServiceAssemblyName = serviceTypeInfo.Last();

			// prepare the type of the service component
			try
			{
				this.PrepareServiceType();
				if (this.ServiceType == null)
				{
					Console.Error.WriteLine(powered);
					Console.Error.WriteLine("");
					Console.Error.WriteLine($"Error: The service component is invalid [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
					if (isUserInteractive)
						Console.ReadLine();
					return;
				}
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine(powered);
				Console.Error.WriteLine("");
				if (ex is ReflectionTypeLoadException reflectionException)
				{
					Console.Error.WriteLine($"Error: The service component [{this.ServiceTypeName},{this.ServiceAssemblyName}] got an unexpected error while preparing");
					reflectionException.LoaderExceptions.ForEach(exception =>
					{
						Console.Error.WriteLine($"{exception.Message} [{exception.GetType()}]\r\nStack: {exception.StackTrace}");
						var inner = exception.InnerException;
						while (inner != null)
						{
							Console.Error.WriteLine($"-------------------------\r\n{inner.Message} [{inner.GetType()}]\r\nStack: {inner.StackTrace}");
							inner = inner.InnerException;
						}
					});
				}
				else
				{
					Console.Error.WriteLine($"Error: The service component [{this.ServiceTypeName},{this.ServiceAssemblyName}] got an unexpected error while preparing => {ex.Message} [{ex.GetType()}]\r\nStack: {ex.StackTrace}");
					var inner = ex.InnerException;
					while (inner != null)
					{
						Console.Error.WriteLine($"-------------------------\r\n{inner.Message} [{inner.GetType()}]\r\nStack: {inner.StackTrace}");
						inner = inner.InnerException;
					}
				}
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// check the type of the service component
			if (!typeof(ServiceBase).IsAssignableFrom(this.ServiceType))
			{
				Console.Error.WriteLine(powered);
				Console.Error.WriteLine("");
				Console.Error.WriteLine($"Error: The service component is invalid [{this.ServiceTypeName},{this.ServiceAssemblyName}] - not assignable");
				if (isUserInteractive)
					Console.ReadLine();
				return;
			}

			// initialize the instance of the service
			var service = this.ServiceType.CreateInstance() as ServiceBase;

			// prepare the signal to start/stop when the service was called from API Gateway
			EventWaitHandle eventWaitHandle = null;
			var useEventWaitHandle = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !isUserInteractive && !doSyncWork;
			if (useEventWaitHandle)
			{
				// get the flag of the existing instance
				var runtimeArguments = Extensions.GetRuntimeArguments();
				var name = $"{service.ServiceURI}#{$"/interactive:{isUserInteractive} /user:{runtimeArguments.Item1} /host:{runtimeArguments.Item2} /platform:{runtimeArguments.Item3} /os:{runtimeArguments.Item4}".GenerateUUID()}";
				eventWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, name, out var createdNew);

				// process the call to stop
				if ("/agc:s".IsEquals(apiCall))
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						eventWaitHandle.Set();

					// then exit
					eventWaitHandle.Dispose();
					service.Dispose();
					return;
				}
			}

			// prepare environment
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare logging
			var loglevel = args?.FirstOrDefault(arg => arg.IsStartsWith("/loglevel:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/loglevel:", "");
			if (string.IsNullOrWhiteSpace(loglevel))
#if DEBUG
				loglevel = UtilityService.GetAppSetting("Logs:Level", "Debug");
#else
				loglevel = UtilityService.GetAppSetting("Logs:Level", "Information");
#endif
			if (!loglevel.TryToEnum(out LogLevel logLevel))
#if DEBUG
				logLevel = LogLevel.Debug;
#else
				logLevel = LogLevel.Information;
#endif

			Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder =>
			{
				builder.SetMinimumLevel(logLevel);
				if (isUserInteractive)
					builder.AddConsole();
			}).BuildServiceProvider().GetService<ILoggerFactory>());
			Components.Caching.Cache.AssignLoggerFactory(Logger.GetLoggerFactory());

			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if ("true".IsEquals(UtilityService.GetAppSetting("Logs:WriteFiles", "true")) && !string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}_" + $"{service.ServiceName.ToLower()}.txt");
				Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

			var logger = (service as IServiceComponent).Logger = Logger.CreateLogger(this.ServiceType);

			// prepare outgoing proxy
			var proxy = UtilityService.GetAppSetting("Proxy:Host");
			if (!string.IsNullOrWhiteSpace(proxy))
				try
				{
					UtilityService.AssignWebProxy(proxy, UtilityService.GetAppSetting("Proxy:Port").CastAs<int>(), UtilityService.GetAppSetting("Proxy:User"), UtilityService.GetAppSetting("Proxy:UserPassword"), UtilityService.GetAppSetting("Proxy:Bypass")?.ToArray(";"));
				}
				catch (Exception ex)
				{
					logger.LogError($"Error occurred while assigning web-proxy => {ex.Message}", ex);
				}

			// setup hooks
			void terminate(string message, bool available = true, bool disconnect = true)
				=> (service.Disposed ? Task.CompletedTask : service.DisposeAsync(args?.ToArray(), available, disconnect, _ => logger.LogInformation(message)).AsTask())
					.ContinueWith(async _ => await Task.Delay(123).ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.Run(true);

			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => terminate($"The service was terminated (by \"process exit\" signal) - Served times: {time.GetElapsedTimes()}", false);

			Console.CancelKeyPress += (sender, arguments) =>
			{
				terminate($"The service was terminated (by \"cancel key press\" signal) - Served times: {time.GetElapsedTimes()}", false);
				Environment.Exit(0);
			};

			// prepare
			ServiceBase.ServiceComponent = service;
			var initializeRepository = !"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", ""));

			// start the service
			if (!doSyncWork || startBeforeDoingSyncWork)
			{
				logger.LogInformation($"The service is starting");
				logger.LogInformation($"Service info: {service.ServiceName} - v{this.ServiceType.Assembly.GetVersion()}");
				logger.LogInformation($"Working mode: {(isUserInteractive ? "Interactive app" : "Background service")}");
				logger.LogInformation($"Starting arguments: {(args != null && args.Count > 0 ? args.Join(" ") : "None")}");

				service.Start(args?.ToArray(), initializeRepository, _ =>
				{
					logger.LogInformation($"API Gateway Router: {new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}");
					logger.LogInformation($"API Gateway HTTP service: {UtilityService.GetAppSetting("HttpUri:APIs", "None")}");
					logger.LogInformation($"Files HTTP service: {UtilityService.GetAppSetting("HttpUri:Files", "None")}");
					logger.LogInformation($"Portals HTTP service: {UtilityService.GetAppSetting("HttpUri:Portals", "None")}");
					logger.LogInformation($"Root (base) directory: {AppDomain.CurrentDomain.BaseDirectory}");
					logger.LogInformation($"Status files directory: {UtilityService.GetAppSetting("Path:Status", "None")}");
					logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:Statics", "None")}");
					logger.LogInformation($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
					logger.LogInformation($"Logging level: {logLevel} - Local rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
					logger.LogInformation($"Show debugs: {service.IsDebugLogEnabled} - Show results: {service.IsDebugResultsEnabled} - Show stacks: {service.IsDebugStacksEnabled}");
					logger.LogInformation($"Service URIs:\r\n\t- Round robin: {service.ServiceURI}\r\n\t- Single (unique): {service.ServiceUniqueURI}");
					logger.LogInformation($"Environment:\r\n\t{Extensions.GetRuntimeEnvironment()}\r\n\t- Node ID: {service.NodeID}\r\n\t- Powered: {powered}");

					stopwatch.Stop();
					logger.LogInformation($"The service was started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");

					if (isUserInteractive && !doSyncWork)
						logger.LogWarning($"=====> Enter \"exit\" to terminate ...............");
				});
			}

			// do the synchronous work
			if (doSyncWork)
			{
				logger.LogInformation($"The service is running with synchronous work - PID: {Process.GetCurrentProcess().Id}");
				if (startBeforeDoingSyncWork)
					Task.Run(async () => await Task.Delay(1234).ConfigureAwait(false)).Run(true);
				else if (initializeRepository)
					service.InitializeRepository();
				service.DoWork(args?.ToArray());
			}

			// wait for exit signal
			else
			{
				if (useEventWaitHandle)
				{
					eventWaitHandle.WaitOne();
					eventWaitHandle.Dispose();
					logger.LogDebug(">>>>> Got \"stop\" call from API Gateway Controller ...............");
				}
				else
				{
					while (Console.ReadLine() != "exit") { }
					if (!isUserInteractive)
						logger.LogDebug(">>>>> Got \"exit\" command from API Gateway Controller ...............");
				}
			}

			terminate($"The service was terminated - Served times: {time.GetElapsedTimes()}");
		}
	}
}