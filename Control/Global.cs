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
		internal static MainForm Form = null;

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
				Global.EventLog.WriteEntry(msg, ex != null ? EventLogEntryType.Error : EventLogEntryType.Information);
			else
				Global.Form.UpdateLogs(msg);

			// write into files
			if (writeFiles)
				Global.Component?._managementService?.WriteLog(serviceName, objectName, log);
		}
		#endregion

		#region Get path for working with logs/emails/webhooks
		static string GetPath(string name, string folder, bool getDefaultIsNotFound = true)
		{
			var path = UtilityService.GetAppSetting(name);
			if (string.IsNullOrWhiteSpace(path) && getDefaultIsNotFound)
				path = Directory.GetCurrentDirectory() + @"\" + folder;
			else if (!string.IsNullOrWhiteSpace(path) && path.EndsWith(@"\"))
				path = path.Left(path.Length - 1);
			return path;
		}

		internal static string LogsPath
		{
			get
			{
				return Global._LogsPath ?? (Global._LogsPath = Global.GetPath("LogsPath", "logs"));
			}
		}

		internal static string StatusPath
		{
			get
			{
				return Global._StatusPath ?? (Global._StatusPath = Global.GetPath("StatusPath", "status"));
			}
		}

		internal static string EmailsPath
		{
			get
			{
				return Global._EmailsPath ?? (Global._EmailsPath = Global.GetPath("EmailsPath", "emails"));
			}
		}

		internal static string WebHooksPath
		{
			get
			{
				return Global._WebHooksPath ?? (Global._WebHooksPath = Global.GetPath("WebHooksPath", "webhooks"));
			}
		}
		#endregion

		#region Email settings
		internal static string EmailSmtpServer
		{
			get
			{
				if (Global._EmailSmtpServer == null)
					Global._EmailSmtpServer = UtilityService.GetAppSetting("EmailSmtpServer", "localhost");
				return Global._EmailSmtpServer;
			}
		}

		internal static int EmailSmtpServerPort
		{
			get
			{
				if (Global._EmailSmtpServerPort < 1)
					Global._EmailSmtpServerPort = UtilityService.GetAppSetting("EmailSmtpServerPort", "25").CastAs<int>();
				return Global._EmailSmtpServerPort;
			}
		}

		internal static string EmailSmtpUser
		{
			get
			{
				if (Global._EmailSmtpUser == null)
					Global._EmailSmtpUser = UtilityService.GetAppSetting("EmailSmtpUser", "");
				return Global._EmailSmtpUser;
			}
		}

		internal static string EmailSmtpUserPassword
		{
			get
			{
				if (Global._EmailSmtpUserPassword == null)
					Global._EmailSmtpUserPassword = UtilityService.GetAppSetting("EmailSmtpUserPassword", "");
				return Global._EmailSmtpUserPassword;
			}
		}

		internal static bool EmailSmtpServerEnableSsl
		{
			get
			{
				if (Global._EmailSmtpServerEnableSsl == null)
					Global._EmailSmtpServerEnableSsl = UtilityService.GetAppSetting("EmailSmtpServerEnableSsl", "false");
				return Global._EmailSmtpServerEnableSsl.IsEquals("true");
			}
		}

		internal static string EmailDefaultSender
		{
			get
			{
				if (Global._EmailDefaultSender == null)
					Global._EmailDefaultSender = UtilityService.GetAppSetting("EmailDefaultSender", "VIEApps.net <vieapps.net@gmail.com>");
				return Global._EmailDefaultSender;
			}
		}
		#endregion

	}
}
