using System;
using System.Runtime.InteropServices;

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static HostComponent HostComponent = new HostComponent();

		static void Main(string[] args)
		{
			if (Environment.UserInteractive)
			{
				Program.ConsoleEventHandler = new ConsoleEventDelegate(Program.ConsoleEventCallback);
				Program.SetConsoleCtrlHandler(Program.ConsoleEventHandler, true);
			}
			Program.HostComponent.Start(args);
		}

		static bool ConsoleEventCallback(int eventCode)
		{
			switch (eventCode)
			{
				case 0:        // Ctrl + C
				case 1:        // Ctrl + Break
				case 2:        // Close
				case 6:        // Shutdown
					Program.HostComponent.Stop();
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