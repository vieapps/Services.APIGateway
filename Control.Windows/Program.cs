#region Related components
using System;
using System.IO;
using System.Windows.Forms;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		internal static CancellationTokenSource CancellationTokenSource = null;
		internal static MainForm MainForm = null;
		internal static ManagementForm ManagementForm = null;
		internal static IServiceManager ServiceManager = null;
		internal static ILoggingService LoggingService = null;
		internal static ControlComponent Component = null;

		[STAThread]
		static void Main(string[] args)
		{
			// initialize
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

			// prepare default settings of Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// prepare logging
#if DEBUG
			var logLevel = LogLevel.Debug;
#else
			var logLevel = LogLevel.Information;
			try
			{
				logLevel = UtilityService.GetAppSetting("Logs:Level", "Information").ToEnum<LogLevel>();
			}
			catch { }
#endif

			var loggerFactory = new ServiceCollection()
				.AddLogging(builder => builder.SetMinimumLevel(logLevel))
				.BuildServiceProvider()
				.GetService<ILoggerFactory>();

			var path = UtilityService.GetAppSetting("Path:Logs");
			if (Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}_apigateway.controller.txt");
				loggerFactory.AddFile(path, logLevel);
			}

			Logger.AssignLoggerFactory(loggerFactory);
			var logger = loggerFactory.CreateLogger<ControlComponent>();

			Global.OnProcess = Global.OnSendRTUMessageSuccess = (message) =>
			{
				logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
			};

			Global.OnSendEmailSuccess = (message) =>
			{
				logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message)).ConfigureAwait(false);
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
			};

			Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnServiceStarted = Global.OnServiceStopped = Global.OnGotServiceMessage = (serviceName, message) =>
			{
				logger.LogInformation($"-- {serviceName} -------\r\n{message}");
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs($"-- {serviceName} -------\r\n{message}");
			};

			Global.OnLogsUpdated = (serviceName, message) =>
			{
				if (!"APIGateway".IsEquals(serviceName))
				{
					logger.LogInformation(message);
					if (Environment.UserInteractive)
						Program.MainForm.UpdateLogs(message);
				}
			};

			// run as a Windows desktop app
			if (Environment.UserInteractive)
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);

				Program.MainForm = new MainForm(args);
				Application.Run(Program.MainForm);
			}

			// run as a Windows service
			else
				System.ServiceProcess.ServiceBase.Run(new ServiceRunner());
		}
	}
}