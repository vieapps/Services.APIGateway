using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Configuration;
using System.Windows.Forms;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		internal static RouterComponent Router { get; set; }

		internal static EventLog EventLog { get; set; }

		internal static ServicePresenter Form { get; set; }

		internal static ILogger Logger { get; set; }

		internal static IDisposable Timer { get; set; }

		static void Main(string[] args)
		{
			if (!Environment.UserInteractive)
				ServiceBase.Run(new ServiceRunner());

			else
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);

				Program.Form = new ServicePresenter();
				Application.Run(Program.Form);
			}
		}

		internal static void Start(string[] args)
		{
			if (!Environment.UserInteractive)
			{
				var name = "Application";
				var source = "VIEApps-APIGateway-Router";

				if (!EventLog.SourceExists(source))
					EventLog.CreateEventSource(source, name);

				Program.EventLog = new EventLog
				{
					Source = source,
					Log = name
				};
			}

			var loglevel = args?.FirstOrDefault(arg => arg.StartsWith("/loglevel:"))?.Replace("/loglevel:", "");
			if (string.IsNullOrWhiteSpace(loglevel))
				loglevel = ConfigurationManager.AppSettings["Logs:Level"];
			if (Enum.TryParse(loglevel, out LogLevel logLevel))
				logLevel = LogLevel.Information;

			var logPath = ConfigurationManager.AppSettings["Logs:Path"];
			var writeLogs = !string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath) && logLevel != LogLevel.None;
			if (writeLogs)
			{
				logPath = Path.Combine(logPath, "{Date}_apigateway.router.txt");
				var loggerFactory = new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>();
				loggerFactory.AddFile(logPath, logLevel);
				Program.Logger = loggerFactory.CreateLogger<RouterComponent>();
			}

			Program.Router = new RouterComponent
			{
				OnError = ex => Program.WriteLog(ex.Message, ex),
				OnStarted = () => Program.WriteLog("VIEApps NGX API Gateway Router was started" + "\r\n\r\n" + Program.Router.RouterInfoString.Replace("\t", "")),
				OnStopped = () => Program.WriteLog("VIEApps NGX API Gateway Router was stopped")
			};
			if (Environment.UserInteractive || writeLogs)
			{
				Program.Router.OnSessionCreated = info => Program.WriteLog(
					(Environment.UserInteractive ? "\r\n\r\n" : "") +
					$"A session was opened" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]"
				);
				Program.Router.OnSessionUpdated = info => Program.WriteLog(
					(Environment.UserInteractive ? "\r\n\r\n" : "") +
					$"A session was updated" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]"
				);
				Program.Router.OnSessionClosed = info => Program.WriteLog(
					(Environment.UserInteractive ? "\r\n\r\n" : "") +
					$"A session was closed" + "\r\n" +
					$"- Session ID: {info.SessionID}" + "\r\n" +
					$"- Connection ID: {info.ConnectionID}" + "\r\n" +
					$"- IP: {info.EndPoint}" + "\r\n" +
					$"- Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]" + "\r\n" +
					$"- Type: {info?.CloseType} ({info?.CloseReason ?? "N/A"})"
				);
			}
			Program.Timer = System.Reactive.Linq.Observable.Timer(TimeSpan.Zero, TimeSpan.FromMinutes(60)).Subscribe(_ =>
			{
				var sessions = "";
				Program.Router.Sessions.Select(kvp => kvp.Value)
					.OrderBy(info => info.EndPoint).ThenBy(info => info.Name).ThenBy(info => info.Description)
					.Select(info => $"\r\n- ID: {info.SessionID} [{info.ConnectionID}] - IP: {info.EndPoint} - Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]")
					.ToList().ForEach(info => sessions += info);
				Program.WriteLog((Environment.UserInteractive ? "\r\n\r\n" : "") + $"Total of sessions: {Program.Router.Sessions.Count}" + sessions);
			});
			Program.Router.Start(args);
		}

		internal static void Stop()
		{
			Program.Router.Stop();
			Program.Timer.Dispose();
			if (!Environment.UserInteractive)
				Program.EventLog.Dispose();
		}

		internal static void WriteLog(string log, Exception ex = null)
		{
			var msg = $"{log}{(ex != null ? $"\r\n\r\n{ex.StackTrace}" : "")}";

			if (ex != null)
				Program.Logger?.LogError(msg, ex);
			else
				Program.Logger?.LogInformation(msg);

			if (Environment.UserInteractive)
				Program.Form.UpdateLogs(msg);
			else
				Program.EventLog.WriteEntry(msg, ex != null ? EventLogEntryType.Error : EventLogEntryType.Information);
		}
	}
}