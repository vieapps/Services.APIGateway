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
		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
		internal static IServiceManager ServiceManager = null;
		internal static ILoggingService LoggingService = null;
		internal static ControlComponent Component = null;

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
				.GetService<ILoggerFactory>()
				.AddConsole();

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
			};

			Global.OnSendEmailSuccess = (message) =>
			{
				logger.LogInformation(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message)).ConfigureAwait(false);
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				logger.LogInformation(message);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
			};

			Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				logger.LogError(message, exception);
				if (Program.LoggingService == null)
					Program.LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
				Task.Run(() => Program.LoggingService.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnServiceStarted = Global.OnServiceStopped = Global.OnGotServiceMessage = (serviceName, message) =>
			{
				logger.LogInformation($"-- {serviceName} -------\r\n{message}");
			};

			Global.OnLogsUpdated = (serviceName, message) =>
			{
				if (!"APIGateway".IsEquals(serviceName))
				{
					logger.LogInformation(message);
				}
			};

			Program.Component = new ControlComponent(Program.CancellationTokenSource.Token);
			Program.Component.Start(args);

			// run as a console app
			if (Environment.UserInteractive)
			{
				Console.ReadLine();
			}

			// run as a system deamon
			else
			{
			}
		}
	}
}
