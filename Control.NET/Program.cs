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

		internal static Controller Controller { get; set; } = null;

		internal static ILogger Logger { get; set; }

		internal static MainForm MainForm { get; set; } = null;

		internal static ManagementForm ManagementForm { get; set; } = null;

		internal static ConcurrentDictionary<string, IServiceManager> ServiceManagers { get; } = new ConcurrentDictionary<string, IServiceManager>();

		internal static ConcurrentDictionary<string, Dictionary<string, bool>> Services { get; } = new ConcurrentDictionary<string, Dictionary<string, bool>>();
		#endregion

		[STAThread]
		static void Main(string[] args)
		{
			// setup environment
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
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
				Program.SetServiceState(Program.Controller.Info.ID, serviceName, true);
				Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				if (Environment.UserInteractive)
				{
					Program.MainForm.UpdateLogs($"[{serviceName.ToLower()}] => {message}");
					Program.MainForm.UpdateServicesInfo();
				}
			};

			Global.OnServiceStopped = (serviceName, message) =>
			{
				Program.SetServiceState(Program.Controller.Info.ID, serviceName, false);
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
			Program.Controller = new Controller(Program.CancellationTokenSource.Token)
			{
				OnInterCommunicateMessageReceived = message =>
				{
					if (message.Type.IsEquals("Controller#Disconnect"))
					{
						var controllerInfo = message.Data.FromJson<ControllerInfo>();
						Program.Services.Values.ForEach(svcSate => svcSate.Remove(controllerInfo.ID));
						Task.Run(() =>
						{
							Program.ManagementForm?.SetControlsState(false, false);
							Program.ManagementForm?.DisplayServices();
						}).ConfigureAwait(false);
					}
					else if (message.Type.IsEquals("Service#Info"))
					{
						var uri = message.Data.Value<string>("URI");
						var controllerID = message.Data.Value<string>("Controller");
						var state = message.Data.Value<string>("State");
						Program.SetServiceState(controllerID, uri, state.IsEquals("Running"));
						Task.Run(() => Program.ManagementForm?.UpdateInfo(controllerID, uri, state)).ConfigureAwait(false);
					}
				}
			};
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

		internal static IServiceManager GetServiceManager(string controllerID)
		{
			if (!Program.ServiceManagers.TryGetValue(controllerID, out IServiceManager serviceManager))
			{
				serviceManager = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create(controllerID));
				Program.ServiceManagers.TryAdd(controllerID, serviceManager);
			}
			return serviceManager;
		}

		internal static void Refresh(string controllerID)
		{
			var serviceManager = Program.GetServiceManager(controllerID);
			if (serviceManager != null)
				try
				{
					serviceManager.GetAvailableBusinessServices().Keys.ForEach(uri => Program.SetServiceState(controllerID, uri, serviceManager.IsBusinessServiceRunning(uri.ToArray('.').Last())));
				}
				catch { }
		}

		internal static void Refresh() => Program.Controller.GetAvailableControllers().ForEach(controller => Program.Refresh(controller.ID));

		internal static void SetServiceState(string controllerID, string name, bool state)
		{
			var uri = name.IndexOf(".") < 0 ? $"net.vieapps.services.{name}" : name;
			if (Program.Services.TryGetValue(uri, out Dictionary<string, bool> info))
				info[controllerID] = state;
			else if (state)
				Program.Services.TryAdd(uri, new Dictionary<string, bool>
				{
					{ controllerID, state }
				});
		}

		internal static bool IsRunning(this Dictionary<string, bool> instances) => instances.Where(kvp => kvp.Value).Count() > 0;
	}
}