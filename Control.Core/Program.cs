#region Related components
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{

		#region Properties
		internal static CancellationTokenSource CancellationTokenSource { get; set; } = null;
		internal static IServiceManager ServiceManager { get; set; } = null;
		internal static ILoggingService LoggingService { get; set; } = null;
		internal static Controller Component { get; set; } = null;
		internal static ILogger Logger { get; set; }
		#endregion

		static void Main(string[] args)
		{
			// initialize
			Console.OutputEncoding = System.Text.Encoding.UTF8;
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

			if (Environment.UserInteractive)
				Components.Utility.Logger.GetLoggerFactory().AddConsole(logLevel);

			Program.Logger = Components.Utility.Logger.CreateLogger<Controller>();

			// setup event handlers
			Program.SetupEventHandlers();

			// start
			Program.Start(args, () =>
			{
				Program.Logger.LogWarning("=> Type 'exit' to terminate.......");
				return Task.CompletedTask;
			});

			// wait for exit
			while (!Console.ReadLine().IsEquals("exit")) { }

			// exit
			Program.Stop();
		}

		static void SetupEventHandlers()
		{
			Global.OnProcess = Global.OnSendRTUMessageSuccess = (message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
					Program.Logger.LogInformation(message);
			};

			Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
			};

			Global.OnLogsUpdated = (serviceName, message) =>
			{
				if (Environment.UserInteractive && (!"APIGateway".IsEquals(serviceName) ? true : !message.IsContains("email message") && !message.IsContains("web-hook message")))
					Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
			};

			Global.OnSendEmailSuccess = (message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
				{
					Program.Logger.LogInformation(message);
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message)).ConfigureAwait(false);
				}
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
				{
					Program.Logger.LogInformation(message);
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
				}
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnServiceStarted = Global.OnServiceStopped = Global.OnGotServiceMessage = (serviceName, message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
					Program.Logger.LogInformation($"[{serviceName}] => {message}");
			};
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));

		internal static IServiceManager GetServiceManager()
			=> Program.ServiceManager ?? (Program.ServiceManager = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create()));

		internal static void Start(string[] args, Func<Task> nextAsync = null)
		{
			Program.CancellationTokenSource = new CancellationTokenSource();
			Program.Component = new Controller(Program.CancellationTokenSource.Token);
			Program.Component.Start(args, nextAsync);
		}

		internal static void Stop()
		{
			Program.Component.Dispose();
			Program.CancellationTokenSource.Cancel();
			Program.CancellationTokenSource.Dispose();
			Program.Logger.LogInformation($"The API Gateway Services Controller is stopped");
		}
	}
}
