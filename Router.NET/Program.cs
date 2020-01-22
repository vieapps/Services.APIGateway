using System;
using System.ServiceProcess;
using System.Windows.Forms;
using System.Diagnostics;

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		internal static RouterComponent Router { get; set; } = null;
		internal static EventLog EventLog { get; set; } = null;
		internal static ServicePresenter Form { get; set; } = null;

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

				Program.EventLog = new EventLog()
				{
					Source = source,
					Log = name
				};
			}

			Program.Router = new RouterComponent
			{
				OnError = ex => Program.WriteLog(ex.Message, ex),
				OnStarted = () => Program.WriteLog(Program.Router.RouterInfoString.Replace("\t", "")),
				OnStopped = () => Program.WriteLog("VIEApps NGX API Gateway Router was stopped"),
				OnSessionCreated = info =>
				{
					if (Environment.UserInteractive)
						Program.WriteLog("\r\n" + $"A session was opened - Session ID: {info.SessionID} - Connection Info: {info.ConnectionID} - {info.EndPoint})");
				},
				OnSessionClosed = info =>
				{
					if (Environment.UserInteractive)
						Program.WriteLog("\r\n" + $"A session was closed - Type: {info?.CloseType} ({info?.CloseReason ?? "N/A"}) - Session ID: {info?.SessionID} - Connection Info: {info?.ConnectionID} - {info?.EndPoint})");
				}
			};
			Program.Router.Start(args);
		}

		internal static void Stop()
		{
			Program.Router.Stop();
			if (!Environment.UserInteractive)
				Program.EventLog.Dispose();
		}

		internal static void WriteLog(string log, Exception ex = null)
		{
			var msg = $"{log}{(ex != null ? $"\r\n\r\n{ex.StackTrace}" : "")}";
			if (Environment.UserInteractive)
				Program.Form.UpdateLogs(msg);
			else
				Program.EventLog.WriteEntry(msg, ex != null ? EventLogEntryType.Error : EventLogEntryType.Information);
		}
	}
}