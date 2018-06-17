#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public static class Program
	{

		#region Properties
		internal static CancellationTokenSource CancellationTokenSource { get; set; } = null;
		internal static ILoggingService LoggingService { get; set; } = null;
		internal static Manager Manager { get; set; } = null;
		internal static Controller Controller { get; set; } = null;
		internal static ILogger Logger { get; set; }
		internal static MainForm MainForm { get; set; } = null;
		internal static ManagementForm ManagementForm { get; set; } = null;
		#endregion

		[STAThread]
		static void Main(string[] args)
		{
			// setup environment
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
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

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>());

			var path = UtilityService.GetAppSetting("Path:Logs");
			if (path != null && Directory.Exists(path))
			{
				path = Path.Combine(path, "{Date}_apigateway.controller.txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(path, logLevel);
			}

			Program.Logger = Components.Utility.Logger.CreateLogger<Controller>();

			// setup event handlers
			Program.SetupEventHandlers();

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

		static void SetupEventHandlers()
		{
			Global.OnProcess = (message) =>
			{
				Program.Logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
			};

			Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
			};

			Global.OnSendRTUMessageSuccess = (message) =>
			{
				if (Program.Logger.IsEnabled(LogLevel.Debug))
					Program.Logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
			};

			Global.OnSendEmailSuccess = (message) =>
			{
				Program.Logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message)).ConfigureAwait(false);
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				Program.Logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnServiceStarted = (serviceName, message) =>
			{
				Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				if (Environment.UserInteractive)
				{
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
					Program.MainForm.UpdateServicesInfo();
				}
			};

			Global.OnServiceStopped = (serviceName, message) =>
			{
				Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				if (Environment.UserInteractive)
				{
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
					Program.MainForm.UpdateServicesInfo();
				}
			};

			Global.OnGotServiceMessage = (serviceName, message) =>
			{
				Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
			};

			Global.OnLogsUpdated = (serviceName, message) =>
			{
				if (Environment.UserInteractive && (!"APIGateway".IsEquals(serviceName) ? true : !message.IsContains("email message") && !message.IsContains("web-hook message")))
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
			};
		}

		internal static void Start(string[] args, Func<Task> nextAsync = null)
		{
			Program.CancellationTokenSource = new CancellationTokenSource();
			Program.Manager = new Manager
			{
				OnServiceStarted = (controllerID, name) =>
				{
					Program.MainForm?.UpdateServicesInfo();
					Program.ManagementForm?.RedisplayService(controllerID, name, "Running");
				},
				OnServiceStopped = (controllerID, name) =>
				{
					Program.MainForm?.UpdateServicesInfo();
					Program.ManagementForm?.RedisplayService(controllerID, name, "Stopped");
				}
			};
			Program.Controller = new Controller(Program.CancellationTokenSource.Token);
			Program.Controller.Start(args, Program.Manager.OnIncomingChannelEstablished, Program.Manager.OnOutgoingChannelEstablished, nextAsync);
		}

		internal static void Stop()
		{
			Program.Manager.Dispose();
			Program.Controller.Dispose();
			Program.CancellationTokenSource.Cancel();
			Program.Logger.LogInformation($"The API Gateway Services Controller is stopped");
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));
	}
}