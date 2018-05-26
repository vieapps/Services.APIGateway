#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections.Generic;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{

		#region Properties
		internal static CancellationTokenSource CancellationTokenSource { get; set; } = null;

		internal static IServiceManager ServiceManager { get; set; } = null;

		internal static ILoggingService LoggingService { get; set; } = null;

		internal static Controller Controller { get; set; } = null;

		internal static ILogger Logger { get; set; }

		internal static MainForm MainForm { get; set; } = null;

		internal static ManagementForm ManagementForm { get; set; } = null;

		internal static Dictionary<string, bool> Services { get; } = new Dictionary<string, bool>();
		#endregion

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
			Global.OnProcess = Global.OnSendRTUMessageSuccess = (message) =>
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
				Program.SetState(serviceName, true);
				Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				if (Environment.UserInteractive)
				{
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
					Program.MainForm.UpdateServicesInfo();
				}
			};

			Global.OnServiceStopped = (serviceName, message) =>
			{
				Program.SetState(serviceName, false);
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
			Program.Controller = new Controller(Program.CancellationTokenSource.Token);
			Program.Controller.Start(args, nextAsync);
		}

		internal static void Stop()
		{
			Program.Controller.Dispose();
			Program.CancellationTokenSource.Cancel();
			Program.Logger.LogInformation($"The API Gateway Services Controller is stopped");
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));

		internal static IServiceManager GetServiceManager()
			=> Program.ServiceManager ?? (Program.ServiceManager = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create()));

		internal static void Refresh()
		{
			var serviceManager = Program.GetServiceManager();
			if (serviceManager != null)
				try
				{
					serviceManager.GetAvailableBusinessServices().Keys.ForEach(uri => Program.Services[uri] = serviceManager.IsBusinessServiceRunning(uri.ToArray('.').Last()));
				}
				catch { }
		}

		internal static void SetState(string name, bool state)
			=> Program.Services[$"net.vieapps.services.{name}"] = state;

		internal static bool GetState(string name)
			=> Program.Services.TryGetValue($"net.vieapps.services.{name}", out bool state)
				? state
				: false;
	}
}