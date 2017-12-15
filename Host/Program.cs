#region Related components
using System;
using System.IO;
using System.Linq;
using System.Xml;
using System.Threading;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static IServiceComponent ServiceComponent;
		static bool IsUserInteractive;

		static void Main(string[] args)
		{
			// prepare
			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var apiCallToStop = apiCall != null && apiCall.IsEquals("/agc:s");

			Program.IsUserInteractive = apiCall == null;
			if (Program.IsUserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

			// prepare type name
			var typeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");
			if (string.IsNullOrWhiteSpace(typeName) && File.Exists("VIEApps.Services.APIGateway.exe.config") && args?.FirstOrDefault(a => a.IsStartsWith("/svn:")) != null)
				try
				{
					var xpath = $"/configuration/net.vieapps.services/add[@name='{args.First(a => a.IsStartsWith("/svn:")).Replace(StringComparison.OrdinalIgnoreCase, "/svn:", "").ToLower()}']";
					var xml = new XmlDocument();
					xml.LoadXml(UtilityService.ReadTextFile("VIEApps.Services.APIGateway.exe.config"));
					typeName = xml.DocumentElement.SelectSingleNode(xpath)?.Attributes["type"]?.Value.Replace(" ", "").Replace(StringComparison.OrdinalIgnoreCase, ",x86", "");
				}
				catch { }

			// stop if has no type name of a service component
			if (string.IsNullOrWhiteSpace(typeName))
			{
				if (Program.IsUserInteractive)
				{
					Console.WriteLine($"VIEApps NGX API Gateway - Service Hoster v{AssemblyName.GetAssemblyName(Assembly.GetExecutingAssembly().Location).Version}");
					Console.WriteLine("");
					Console.WriteLine("Syntax: VIEApps.Services.APIGateway.Host.exe /svc:<service-component-namespace,service-assembly>");
					Console.WriteLine("");
					Console.WriteLine("Ex.: VIEApps.Services.APIGateway.Host.exe /svc:net.vieapps.Services.Systems.ServiceComponent,VIEAApps.Services.Systems");
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
				if (Program.IsUserInteractive)
					Console.ReadLine();
				return;
			}

			Program.ServiceComponent = serviceType.CreateInstance() as IServiceComponent;
			if (Program.ServiceComponent == null || !(Program.ServiceComponent is IService))
			{
				Console.WriteLine($"The type of the service component is invalid [{serviceType.GetTypeName()}]");
				if (Program.IsUserInteractive)
					Console.ReadLine();
				return;
			}
			else
				Program.ServiceComponent.IsUserInteractive = Program.IsUserInteractive;

			// prepare default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Newtonsoft.Json.Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare logging
			var logger = new ServiceCollection()
				.AddLogging(builder =>
				{
#if DEBUG
					builder.SetMinimumLevel(LogLevel.Debug);
#else
					builder.SetMinimumLevel(LogLevel.Information);
#endif
					builder.AddConsole();
				})
				.BuildServiceProvider()
				.GetService<ILoggerFactory>()
				.CreateLogger(Program.ServiceComponent.GetType());

			// prepare the signal to start/stop when the service was called from API Gateway
			EventWaitHandle waitHandle = null;
			if (!Program.IsUserInteractive)
			{
				// get the flag of the existing instance
				waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, (Program.ServiceComponent as IService).ServiceURI, out bool createdNew);

				// process the call to stop
				if (apiCallToStop)
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						waitHandle.Set();

					// then exit
					Program.ServiceComponent.Dispose();
					return;
				}
			}
			else
				logger.LogInformation($"The service [{(Program.ServiceComponent as IService).ServiceURI}] is starting...");

			// start the service component
			var initRepository = args?.FirstOrDefault(a => a.IsStartsWith("/repository:"));
			Program.ServiceComponent.Start(args, !string.IsNullOrWhiteSpace(initRepository) && initRepository.IsEquals("false") ? false : true);

			// wait for exit
			if (Program.IsUserInteractive)
			{
				Program.ConsoleEventHandler = new ConsoleEventDelegate(Program.ConsoleEventCallback);
				Program.SetConsoleCtrlHandler(Program.ConsoleEventHandler, true);
				logger.LogInformation($"The service [{(Program.ServiceComponent as IService).ServiceURI}] is started. PID: {Process.GetCurrentProcess().Id}\r\n=====> Press RETURN to terminate...");
				Console.ReadLine();
			}
			else
			{
				waitHandle.WaitOne();
				Program.ServiceComponent.Dispose();
			}
		}

		static bool ConsoleEventCallback(int eventCode)
		{
			switch (eventCode)
			{
				case 0:        // Ctrl + C
				case 1:        // Ctrl + Break
				case 2:        // Close
				case 6:        // Shutdown
					Program.ServiceComponent.Dispose();
					break;
			}
			return false;
		}

		// keeps it from getting garbage collected
		static ConsoleEventDelegate ConsoleEventHandler;

		// invokes
		delegate bool ConsoleEventDelegate(int eventCode);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);
	}
}