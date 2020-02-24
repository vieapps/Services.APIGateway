using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using net.vieapps.Components.Utility;

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
			var loglevel = args?.FirstOrDefault(a => a.IsStartsWith("/loglevel:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/loglevel:", "");
			if (string.IsNullOrWhiteSpace(loglevel))
#if DEBUG
				loglevel = UtilityService.GetAppSetting("Logs:Level", "Debug");
#else
				loglevel = UtilityService.GetAppSetting("Logs:Level", "Information");
#endif
			if (!loglevel.TryToEnum(out LogLevel logLevel))
#if DEBUG
				logLevel = LogLevel.Debug;
#else
				logLevel = LogLevel.Information;
#endif

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder => builder.SetMinimumLevel(logLevel)).BuildServiceProvider().GetService<ILoggerFactory>());

			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (logPath != null && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}_apigateway.controller.txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

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
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "Emails", message)).ConfigureAwait(false);
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				Program.Logger.LogInformation(message);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				if (Environment.UserInteractive)
					Program.MainForm.UpdateLogs(message);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
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
			Task.WaitAll(new[] { Program.Manager.DisposeAsync(), Program.Controller.DisposeAsync() }, 3456);
			Program.CancellationTokenSource.Cancel();
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = Router.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));
	}
}