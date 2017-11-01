#region Related components
using System;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		internal static IServiceComponent Component = null;
		internal static bool AsService = false;

		static void Main(string[] args)
		{
			// get type of service
			var apiType = args?.FirstOrDefault(a => a.IsStartsWith("/svc:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/svc:", "");

			// get flag to run or stop (when called from API Gateway)
			var apiCall = args?.FirstOrDefault(a => a.IsStartsWith("/agc:"));
			var apiCallToStop = apiCall != null && apiCall.IsEquals("/agc:s");
			Program.AsService = apiCall != null;

			// initialize the instance of service component
			if (string.IsNullOrWhiteSpace(apiType))
			{
				Console.WriteLine("VIEApps NGX API Gateway Hosting.....");
				Console.WriteLine("");
				Console.WriteLine("\tSyntax: VIEApps.Services.APIGateway.Host.exe /svc:<service-namespace,service-assembly>");
				Console.WriteLine("\tEx: VIEApps.Services.APIGateway.Host.exe /svc:net.vieapps.Services.System,VIEAApps.Services.System");
				return;
			}

			var svcType = Type.GetType(apiType);
			if (svcType == null)
			{
				Console.WriteLine("The type is not found [" + apiType + "]");
				return;
			}

			Program.Component = svcType.CreateInstance() as IServiceComponent;
			if (Program.Component == null || !(Program.Component is IService))
			{
				Console.WriteLine("The type is invalid [" + svcType.GetTypeName() + "]");
				return;
			}

			// prepare the signal to start/stop
			EventWaitHandle waitHandle = null;
			if (Program.AsService)
			{
				// get the flag of the existing instance
				waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, (Program.Component as IService).ServiceURI, out bool createdNew);
				
				// process the call to stop
				if (apiCallToStop)
				{
					// raise an event to stop current existing instance
					if (!createdNew)
						waitHandle.Set();

					// then exit
					Program.Component.Dispose();
					return;
				}
			}

			// start the service component
			if (!Program.AsService)
			{
				Console.OutputEncoding = System.Text.Encoding.UTF8;
				Console.WriteLine("Starting the service [" + (Program.Component as IService).ServiceURI + "]");
				Console.WriteLine("=====> Press RETURN to terminate...");
			}

			var apiInitRepository = args?.FirstOrDefault(a => a.IsStartsWith("/repository:"));
			var initializeRepository = !string.IsNullOrWhiteSpace(apiInitRepository) && apiInitRepository.IsEquals("false")
				? false
				: true;
			Program.Component.Start(args, initializeRepository);

			// wait for exit
			if (Program.AsService)
			{
				waitHandle.WaitOne();
				Program.Component.Dispose();
			}
			else
			{
				Program.ConsoleEventHandler = new ConsoleEventDelegate(Program.ConsoleEventCallback);
				Program.SetConsoleCtrlHandler(Program.ConsoleEventHandler, true);
				Console.ReadLine();
			}
		}

		#region Closing event handler
		static bool ConsoleEventCallback(int eventCode)
		{
			switch (eventCode)
			{
				case 0:		// Ctrl + C
				case 1:		// Ctrl + Break
				case 2:		// Close
				case 6:		// Shutdown
					Program.Component.Dispose();
					break;
			}
			return false;
		}

		// keeps it from getting garbage collected
		static ConsoleEventDelegate ConsoleEventHandler;

		// invokes
		private delegate bool ConsoleEventDelegate(int eventCode);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);
		#endregion

	}
}