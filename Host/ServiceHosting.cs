using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
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

		public void Run(string[] args)
		{
			try
			{
				this.RunInternal(args);
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("Error: The service component was got an unexpected error => " + ex.Message);
				Console.Error.WriteLine(ex.StackTrace);
			}
		}

		protected void RunInternal(string[] args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			var time = DateTime.Now;
			var stopwatch = Stopwatch.StartNew();

			var apiCall = args?.FirstOrDefault(arg => arg.IsStartsWith("/agc:"));
			var isUserInteractive = Environment.UserInteractive && apiCall == null;
			var hostingInfo = $"VIEApps NGX API Gateway - Service Hosting {RuntimeInformation.ProcessArchitecture.ToString().ToLower()} {Assembly.GetCallingAssembly().GetVersion()}";

			// prepare type name
			this.ServiceTypeName = args?.FirstOrDefault(arg => arg.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			if (string.IsNullOrWhiteSpace(this.ServiceTypeName) && args?.FirstOrDefault(arg => arg.IsStartsWith("/svn:")) != null)
			{
				var configFilename = Path.Combine($"{UtilityService.GetAppSetting("Path:APIGateway:Controller")}", $"VIEApps.Services.APIGateway.{(RuntimeInformation.FrameworkDescription.IsContains(".NET Framework") ? "exe" : "dll")}.config");
				if (File.Exists(configFilename))
					try
					{
						var xml = new System.Xml.XmlDocument();
						xml.LoadXml(UtilityService.ReadTextFile(configFilename));
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
				Console.Error.WriteLine(hostingInfo);
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
			this.ServiceTypeName = serviceTypeInfo[0];
			this.ServiceAssemblyName = serviceTypeInfo.Length > 1 ? serviceTypeInfo[1] : "Unknown";

			// prepare the type of the service component
			try
			{
				this.PrepareServiceType();
				if (this.ServiceType == null)
				{
					Console.Error.WriteLine(hostingInfo);
					Console.Error.WriteLine("");
					Console.Error.WriteLine($"Error: The service component is invalid [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
					if (isUserInteractive)
						Console.ReadLine();
					return;
				}
			}
			catch (Exception ex)
			{
				if (ex is ReflectionTypeLoadException)
				{
					Console.Error.WriteLine(hostingInfo);
					Console.Error.WriteLine("");
					Console.Error.WriteLine($"Error: The service component [{this.ServiceTypeName},{this.ServiceAssemblyName}] got an unexpected error while preparing");
					(ex as ReflectionTypeLoadException).LoaderExceptions.ForEach(exception =>
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
					Console.Error.WriteLine(hostingInfo);
					Console.Error.WriteLine("");
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
			if (!typeof(IServiceComponent).IsAssignableFrom(this.ServiceType) || !typeof(ServiceBase).IsAssignableFrom(this.ServiceType))
			{
				Console.Error.WriteLine(hostingInfo);
				Console.Error.WriteLine("");
				Console.Error.WriteLine($"Error: The service component is invalid [{this.ServiceTypeName},{this.ServiceAssemblyName}]");
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
				var name = $"{serviceComponent.ServiceURI}#{args.Where(arg => !arg.IsStartsWith("/agc:") && !arg.IsStartsWith("/controller-id:")).Join("#").GenerateUUID()}";
				eventWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, name, out var createdNew);

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
			if (!string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}_" + $"{serviceComponent.ServiceName.ToLower()}.all.txt");
				Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

			var logger = serviceComponent.Logger = Logger.CreateLogger(this.ServiceType);

			// setup hooks
			bool stopped = false;
			void stop()
			{
				stopped = true;
				serviceComponent.Stop(args);
				serviceComponent.Dispose();
			}

			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) =>
			{
				if (!stopped)
				{
					stop();
					logger.LogInformation($"The service is stopped (by \"process exit\" signal) - Served times: {time.GetElapsedTimes()}");
				}
			};

			Console.CancelKeyPress += (sender, arguments) =>
			{
				if (!stopped)
				{
					stop();
					logger.LogInformation($"The service is stopped (by \"cancel key press\" signal) - Served times: {time.GetElapsedTimes()}");
				}
				Environment.Exit(0);
			};

			// start the service component
			logger.LogInformation($"The {serviceComponent.ServiceName} service is starting");
			logger.LogInformation($"Version: {this.ServiceType.Assembly.GetVersion()}");
			logger.LogInformation($"Mode: {(isUserInteractive ? "Interactive app" : "Background service")}");
			logger.LogInformation($"Platform: {Extensions.GetRuntimePlatform()}");
			logger.LogInformation($"Starting arguments: {(args != null && args.Length > 0 ? args.Join(" ") : "None")}");

			ServiceBase.ServiceComponent = serviceComponent as ServiceBase;
			try
			{
				serviceComponent.Start(
					args,
					"false".IsEquals(args?.FirstOrDefault(a => a.IsStartsWith("/repository:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/repository:", "")) ? false : true,
					service =>
					{
						logger.LogInformation($"API Gateway Router: {new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}");
						logger.LogInformation($"API Gateway HTTP service: {UtilityService.GetAppSetting("HttpUri:APIs", "None")}");
						logger.LogInformation($"Files HTTP service: {UtilityService.GetAppSetting("HttpUri:Files", "None")}");
						logger.LogInformation($"Portals HTTP service: {UtilityService.GetAppSetting("HttpUri:Portals", "None")}");
						logger.LogInformation($"Passport HTTP service: {UtilityService.GetAppSetting("HttpUri:Passports", "None")}");
						logger.LogInformation($"Root (base) directory: {AppDomain.CurrentDomain.BaseDirectory}");
						logger.LogInformation($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
						logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:StaticFiles", "None")}");
						logger.LogInformation($"Logging level: {logLevel} - Local rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
						logger.LogInformation($"Show debugs: {(service as ServiceBase).IsDebugLogEnabled} - Show results: {(service as ServiceBase).IsDebugResultsEnabled} - Show stacks: {(service as ServiceBase).IsDebugStacksEnabled}");
						logger.LogInformation($"Service URIs:\r\n\t- Round robin: {service.ServiceURI}\r\n\t- Single (unique): {(service as IUniqueService).ServiceUniqueURI}");

						stopwatch.Stop();
						logger.LogInformation($"The service is started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");

						if (isUserInteractive)
							logger.LogWarning($"=====> Enter \"exit\" to terminate ...............");

						return Task.CompletedTask;
					}
				);
			}
			catch (Exception ex)
			{
				logger.LogError($">>>>> Error occurred while starting the service: {ex.Message}", ex);
				eventWaitHandle?.Dispose();
				stop();
				return;
			}

			// wait for exit signal
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

			stop();
			logger.LogInformation($"The service is stopped - Served times: {time.GetElapsedTimes()}");
		}
	}
}