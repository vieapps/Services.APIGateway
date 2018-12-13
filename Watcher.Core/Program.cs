using System;
namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args)
		{
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => ServiceWatcher.Stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				ServiceWatcher.Stop();
				Environment.Exit(0);
			};
			ServiceWatcher.Start(args);
			while (true)
				System.Threading.Tasks.Task.Delay(54321).GetAwaiter().GetResult();
		}
	}
}