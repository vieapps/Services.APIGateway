using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			var isUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;
			var loggerFactory = new ServiceCollection()
				.AddLogging(builder =>
				{
					builder.SetMinimumLevel(LogLevel.Information);
					if (isUserInteractive)
						builder.AddConsole();
				})
				.BuildServiceProvider()
				.GetService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger<RouterComponent>();
			RouterComponent router = null;

			void showInfo()
			{
				logger.LogInformation("Info:" + "\r\n\t" + router.RouterInfoString);
			}

			void showCommands()
			{
				logger.LogInformation(
					$"Commands:" + "\r\n\t" +
					$"- info: show the router information" + "\r\n\t" +
					$"- sessions: show all the sessions" + "\r\n\t" +
					$"- help: show the available commands" + "\r\n\t" +
					$"- exit: shutdown and terminate"
				);
			}

			void processCommands()
			{
				var command = Console.ReadLine();
				while (command != null)
				{
					if (command.ToLower().Equals("exit"))
						return;

					else if (command.ToLower().Equals("info"))
						showInfo();

					else if (command.ToLower().Equals("sessions"))
						logger.LogInformation(router.SessionsInfoString);

					else
						showCommands();

					command = Console.ReadLine();
				}
			}

			void stop()
			{
				router.OnError = null;
				router.Stop();
			}

			// setup hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				stop();
				Environment.Exit(0);
			};

			// start
			router = isUserInteractive && args?.FirstOrDefault(a => a.StartsWith("/docker")) == null
				? new RouterComponent
				{
					OnError = ex => logger.LogError(ex, ex.Message),
					OnStarted = () =>
					{
						logger.LogInformation("VIEApps NGX API Gateway Router is ready for serving");
						showInfo();
						showCommands();
					},
					OnStopped = () => logger.LogInformation("VIEApps NGX API Gateway Router is stopped"),
					OnSessionCreated = info => logger.LogInformation($"A session is opened - Session ID: {info.SessionID} - Connection Info: {info.ConnectionID} - {info.EndPoint})"),
					OnSessionClosed = info => logger.LogInformation($"A session is closed - Type: {info?.CloseType} ({info?.CloseReason ?? "N/A"}) - Session ID: {info?.SessionID} - Connection Info: {info?.ConnectionID} - {info?.EndPoint})")
				}
				: new RouterComponent
				{
					OnError = ex => Console.Error.WriteLine(ex.Message + "\r\n" + ex.StackTrace),
					OnStarted = () => Console.WriteLine("VIEApps NGX API Gateway Router is ready for serving" + "\r\n\t" + router.RouterInfoString + "\r\n\t" + $"- Starting time: {DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")}"),
					OnStopped = () => Console.WriteLine("VIEApps NGX API Gateway Router is stopped\r\n")
				};

			router.Start(args);

			// processing commands util got an exit signal
			if (isUserInteractive && args?.FirstOrDefault(a => a.StartsWith("/docker")) == null)
				processCommands();

			// wait until be killed
			else
				while (true)
					Task.Delay(54321).GetAwaiter().GetResult();

			// stop
			stop();
		}
	}
}