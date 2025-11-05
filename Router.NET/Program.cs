using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Configuration;
using System.ServiceProcess;
using System.Windows.Forms;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		internal static RouterComponent Router { get; set; }

		internal static EventLog EventLog { get; set; }

		internal static ServicePresenter Form { get; set; }

		internal static Microsoft.Extensions.Logging.ILogger Logger { get; set; }

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
			var writeLogs = !string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath);
			if (writeLogs)
				Program.Logger = new ServiceCollection()
					.AddLogging(builder => builder.SetMinimumLevel(logLevel))
					.BuildServiceProvider()
					.GetService<ILoggerFactory>()
					.AddSerilog(new LoggerConfiguration().WriteTo
						.File(path: Path.Combine(logPath, "apigateway.router-.txt"), rollingInterval: RollingInterval.Day)
						.CreateLogger()
					)
					.CreateLogger<RouterComponent>();

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
			Program.Timer = System.Reactive.Linq.Observable.Timer(TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(60)).Subscribe(_ =>
			{
				var sessions = "";
				Program.Router.Sessions.Select(kvp => kvp.Value).Select(info => (IP: info.EndPoint.Address.ToString(), Info: info)).ToList()
					.OrderBy(kvp => kvp.IP).ThenBy(kvp => kvp.Info.Name).ThenBy(kvp => kvp.Info.Description).Select(kvp => kvp.Info)
					.Select(info => $"\r\n- ID: {info.SessionID} [{info.ConnectionID}] - IP: {info.EndPoint} - Service: {info.Name ?? "N/A"} [{info.Description ?? "N/A"}]")
					.ToList().ForEach(info => sessions += info);
				Program.WriteLog((Environment.UserInteractive ? "\r\n\r\n" : "") + $"Total of sessions: {Program.Router.Sessions.Count}" + sessions);
			}, _ => { });
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