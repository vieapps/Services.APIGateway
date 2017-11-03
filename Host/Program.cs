#region Related components
using System;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static IServiceComponent ServiceComponent = null;
		static bool IsUserInteractive = false;

		static void Main(string[] args)
		{
			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Newtonsoft.Json.Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare
			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var apiCallToStop = apiCall != null && apiCall.IsEquals("/agc:s");
			var typeName = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");

			Program.IsUserInteractive = apiCall == null;
			if (Program.IsUserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

			// initialize the instance of service component
			if (string.IsNullOrWhiteSpace(typeName))
			{
				Console.WriteLine("VIEApps NGX API Gateway - Service Hosting v10.1");
				Console.WriteLine("");
				Console.WriteLine("Syntax: VIEApps.Services.APIGateway.Host.exe /svc:<service-component-namespace,service-assembly>");
				Console.WriteLine("");
				Console.WriteLine("Ex.: VIEApps.Services.APIGateway.Host.exe /svc:net.vieapps.Services.Systems.ServiceComponent,VIEAApps.Services.Systems");
				if (Program.IsUserInteractive)
					Console.ReadLine();
				return;
			}

			var serviceType = Type.GetType(typeName);
			if (serviceType == null)
			{
				Console.WriteLine("The type of the service component is not found [" + typeName + "]");
				if (Program.IsUserInteractive)
					Console.ReadLine();
				return;
			}

			Program.ServiceComponent = serviceType.CreateInstance() as IServiceComponent;
			if (Program.ServiceComponent == null || !(Program.ServiceComponent is IService))
			{
				Console.WriteLine("The type of the service component is invalid [" + serviceType.GetTypeName() + "]");
				if (Program.IsUserInteractive)
					Console.ReadLine();
				return;
			}
			else
				Program.ServiceComponent.IsUserInteractive = Program.IsUserInteractive;

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

			// start the service component
			if (Program.IsUserInteractive)
				Console.WriteLine("Starting the service [" + (Program.ServiceComponent as IService).ServiceURI + "]");

			var initRepository = args?.FirstOrDefault(a => a.IsStartsWith("/repository:"));
			Program.ServiceComponent.Start(args, !string.IsNullOrWhiteSpace(initRepository) && initRepository.IsEquals("false") ? false : true);

			// wait for exit
			if (Program.IsUserInteractive)
			{
				Program.ConsoleEventHandler = new ConsoleEventDelegate(Program.ConsoleEventCallback);
				Program.SetConsoleCtrlHandler(Program.ConsoleEventHandler, true);
				Console.WriteLine("=====> Press RETURN to terminate...");
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
				case 0:		// Ctrl + C
				case 1:		// Ctrl + Break
				case 2:		// Close
				case 6:		// Shutdown
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