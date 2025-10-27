using System;
using System.IO;
using System.Linq;
using System.Configuration;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			RouterComponent router = null;
			IDisposable timer = null;

			var isUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;
			var logPath = ConfigurationManager.AppSettings["Logs:Path"];
			var logger = new ServiceCollection().AddLogging(builder =>
			{
				builder.SetMinimumLevel(LogLevel.Information);
				if (isUserInteractive)
					builder.AddConsole();
				if (!string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
					builder.AddSerilog(new LoggerConfiguration().WriteTo
						.File(path: Path.Combine(logPath, "apigateway.router..txt"), rollingInterval: RollingInterval.Day)
						.CreateLogger()
					);
			})
			.BuildServiceProvider()
			.GetService<ILoggerFactory>()
			.CreateLogger<RouterComponent>();

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
				timer?.Dispose();
			}

			// setup hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				stop();
				Environment.Exit(0);
			};

			// start
			router = new RouterComponent
			{
				OnError = ex => logger.LogError(ex, ex.Message),
				OnStarted = () =>
				{
					logger.LogInformation("VIEApps NGX API Gateway Router was started" + "\r\n\r\n" + router.RouterInfoString.Replace("\t", ""));
					if (isUserInteractive && args?.FirstOrDefault(a => a.StartsWith("/docker")) == null)
						showCommands();
				},
				OnStopped = () => logger.LogInformation("VIEApps NGX API Gateway Router was stopped")
			};

			if (isUserInteractive && args?.FirstOrDefault(a => a.StartsWith("/docker")) == null)
			{
				router.OnSessionCreated = info => logger.LogInformation(
					(isUserInteractive ? "\r\n\r\n" : "") +
					$"A session was opened" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]"
				);
				router.OnSessionUpdated = info => logger.LogInformation(
					(isUserInteractive ? "\r\n\r\n" : "") +
					$"A session was updated" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]"
				);
				router.OnSessionClosed = info => logger.LogInformation(
					(isUserInteractive ? "\r\n\r\n" : "") +
					$"A session was closed" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]" + "\r\n" +
					$"- Type: {info?.CloseType} ({info?.CloseReason ?? "N/A"})"
				);
				timer = System.Reactive.Linq.Observable.Timer(TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(60)).Subscribe(_ =>
				{
					var sessions = "";
					router.Sessions.Select(kvp => kvp.Value).Select(info => (IP: info.EndPoint.Address.ToString(), Info: info)).ToList()
						.OrderBy(kvp => kvp.IP).ThenBy(kvp => kvp.Info.Name).ThenBy(kvp => kvp.Info.Description).Select(kvp => kvp.Info)
						.Select(info => $"\r\n- ID: {info.SessionID} [{info.ConnectionID}] - IP: {info.EndPoint} - Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]")
						.ToList().ForEach(info => sessions += info);
					logger.LogInformation((isUserInteractive ? "\r\n\r\n" : "") + $"Total of sessions: {router.Sessions.Count}" + sessions);
				}, _ => { });
			}

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