#region Related components
using System;
using System.IO;
using System.Threading;
using System.Diagnostics;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Global
	{
		internal static bool AsService = true;
		internal static ServiceComponent Component = null;
		internal static IServiceManager ServiceManager = null;

		internal static MainForm MainForm = null;
		internal static ServicesForm ManagementForm = null;

		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
		static string _LogsPath = null, _StatusPath = null, _EmailsPath = null, _WebHooksPath = null;
		static string _EmailSmtpServer = null, _EmailSmtpServerEnableSsl = null, _EmailSmtpUser = null, _EmailSmtpUserPassword = null, _EmailDefaultSender = null;
		static int _EmailSmtpServerPort = 0;

		#region Working with logs
		static EventLog EventLog = null;

		internal static void InitializeLog()
		{
			if (Global.EventLog == null)
			{
				var logName = "Application";
				var logSource = "VIEApps API Gateway";

				if (!EventLog.SourceExists(logSource))
					EventLog.CreateEventSource(logSource, logName);

				Global.EventLog = new EventLog(logSource)
				{
					Source = logSource,
					Log = logName
				};
			}
		}

		internal static void DisposeLog()
		{
			Global.EventLog.Close();
			Global.EventLog.Dispose();
		}

		internal static void WriteLog(string log, Exception ex = null, bool writeFiles = false, string serviceName = null, string objectName = null)
		{
			// update logs
			string msg = log + (ex != null ? "\r\n\r\n" + "Message: " + ex.Message + " [" + ex.GetType().ToString() + "]\r\n\r\n" + "Details: " + ex.StackTrace : "");
			if (Global.AsService)
				try
				{
					Global.EventLog.WriteEntry(msg, ex != null ? EventLogEntryType.Error : EventLogEntryType.Information);
				}
				catch { }
			else
				Global.MainForm.UpdateLogs(msg);

			// write into files
			if (writeFiles)
				Global.Component?._loggingService?.WriteLog(serviceName, objectName, log);
		}
		#endregion

		#region Get path for working with logs/emails/webhooks
		static string GetPath(string name, string folder, bool getDefaultIsNotFound = true)
		{
			var path = UtilityService.GetAppSetting(name);
			if (string.IsNullOrWhiteSpace(path) && getDefaultIsNotFound)
				path = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString() + folder;
			else if (!string.IsNullOrWhiteSpace(path) && path.EndsWith(Path.DirectorySeparatorChar.ToString()))
				path = path.Left(path.Length - 1);
			return path;
		}

		internal static string LogsPath
		{
			get
			{
				return Global._LogsPath ?? (Global._LogsPath = Global.GetPath("Path:Logs", "logs"));
			}
		}

		internal static string StatusPath
		{
			get
			{
				return Global._StatusPath ?? (Global._StatusPath = Global.GetPath("Path:Status", "status"));
			}
		}

		internal static string EmailsPath
		{
			get
			{
				return Global._EmailsPath ?? (Global._EmailsPath = Global.GetPath("Path:Emails", "emails"));
			}
		}

		internal static string WebHooksPath
		{
			get
			{
				return Global._WebHooksPath ?? (Global._WebHooksPath = Global.GetPath("Path:WebHooks", "webhooks"));
			}
		}
		#endregion

		#region Email settings
		internal static string EmailSmtpServer
		{
			get
			{
				return Global._EmailSmtpServer ?? (Global._EmailSmtpServer = UtilityService.GetAppSetting("Email:SmtpServer", "localhost"));
			}
		}

		internal static int EmailSmtpServerPort
		{
			get
			{
				if (Global._EmailSmtpServerPort < 1)
					Global._EmailSmtpServerPort = UtilityService.GetAppSetting("Email:SmtpServerPort", "25").CastAs<int>();
				return Global._EmailSmtpServerPort;
			}
		}

		internal static string EmailSmtpUser
		{
			get
			{
				return Global._EmailSmtpUser ?? (Global._EmailSmtpUser = UtilityService.GetAppSetting("Email:SmtpUser", ""));
			}
		}

		internal static string EmailSmtpUserPassword
		{
			get
			{
				return Global._EmailSmtpUserPassword ?? (Global._EmailSmtpUserPassword = UtilityService.GetAppSetting("Email:SmtpUserPassword", ""));
			}
		}

		internal static bool EmailSmtpServerEnableSsl
		{
			get
			{
				return (Global._EmailSmtpServerEnableSsl ?? (Global._EmailSmtpServerEnableSsl = UtilityService.GetAppSetting("Email:SmtpServerEnableSsl", "false"))).IsEquals("true");
			}
		}

		internal static string EmailDefaultSender
		{
			get
			{
				return Global._EmailDefaultSender ?? (Global._EmailDefaultSender = UtilityService.GetAppSetting("Email:DefaultSender", "VIEApps.net <vieapps.net@gmail.com>"));
			}
		}
		#endregion

	}
}
