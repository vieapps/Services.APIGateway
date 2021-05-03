using System;
using System.Threading.Tasks;
namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		[STAThread]
		static void Main(string[] args)
		{
			if (Environment.UserInteractive)
			{
				ServiceWatcher.Start(args, () =>
				{
					Task.WaitAll(Task.Delay(1234));
					Console.WriteLine("\r\n\r\nType \"exit\" to terminate the app...\r\n\r\n");
				});
				while (Console.ReadLine() != "exit") { }
				ServiceWatcher.Stop(() => Console.WriteLine("\r\nThe app was terminated...\r\n\r\n"));
			}
			else
			{
				System.ServiceProcess.ServiceBase.Run(new[] { new ServiceRunner() });
			}
		}
	}
}