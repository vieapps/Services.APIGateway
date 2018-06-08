#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

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
		internal static Controller Controller { get; set; } = null;
		internal static ILogger Logger { get; set; }
		internal static bool IsUserInteractive { get; set; } = false;
		#endregion

		static void Main(string[] args)
		{
			// prepare environment
			Program.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
			Console.OutputEncoding = System.Text.Encoding.UTF8;
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

			if (Program.IsUserInteractive)
				Components.Utility.Logger.GetLoggerFactory().AddConsole(logLevel);

			Program.Logger = Components.Utility.Logger.CreateLogger<Controller>();

			// setup event handlers
			Program.SetupEventHandlers();

			void showCommands()
			{
				Program.Logger.LogInformation(
					"VIEApps NGX Services Controller commands:" + "\r\n\t" +
					"start <name>: start a business service that specified by name" + "\r\n\t" +
					"stop <name>: stop a business service that specified by name" + "\r\n\t" +
					"restart: restart all business services" + "\r\n\t" +
					"info: show the information of all business services and others" + "\r\n\t" +
					"help: show available commands" + "\r\n\t" +
					"exit: shutdown & terminate"
				);
			}

			void processCommands()
			{
				var command = Console.ReadLine();
				while (command != null)
				{
					if (command.ToLower() == "exit")
						return;

					var commands = command.ToArray(' ');

					if (commands[0].IsStartsWith("start"))
					{
						if (commands.Length > 1)
							Program.Controller.StartBusinessService(commands[1], Program.Controller.GetServiceArguments().Replace("/", "/call-"), null);
						else
							Program.Logger.LogInformation($"Invalid {command} command");
					}

					else if (commands[0].IsStartsWith("stop"))
					{
						if (commands.Length > 1)
							Program.Controller.StopBusinessService(commands[1], null);
						else
							Program.Logger.LogInformation($"Invalid {command} command");
					}

					else if (commands[0].IsEquals("restart"))
					{
						Program.Logger.LogInformation("Attempting to stop all business services...");
						Program.Controller.GetAvailableBusinessServices().ForEach(kvp => Program.Controller.StopBusinessService(kvp.Key.ToArray('.').Last(), null));
						Task.Run(async () =>
						{
							Program.Logger.LogInformation("Attempting to re-start all business services...");
							await Task.Delay(UtilityService.GetRandomNumber(2345, 3456)).ConfigureAwait(false);
							var arguments = Program.Controller.GetServiceArguments();
							Program.Controller.GetAvailableBusinessServices().ForEach(kvp => Task.Run(() => Program.Controller.StartBusinessService(kvp.Key.ToArray('.').Last(), arguments, null)));
						}).ConfigureAwait(false);
					}

					else if (commands[0].IsEquals("info"))
					{
						var info = "";

						info +=
							$"Controller:" + "\r\n\t" +
							$"- Version: {typeof(Controller).Assembly.GetVersion()}" + "\r\n\t" +
							$"- Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : $"Other OS")} {RuntimeInformation.OSArchitecture} ({RuntimeInformation.OSDescription.Trim()})" + "\r\n\t" +
							$"- Working mode: {(Environment.UserInteractive ? "Interactive App" : "Background Service")}" + "\r\n\t" +
							$"- WAMP router URI: {WAMPConnections.GetRouterStrInfo()}" + "\r\n\t" +
							$"- Incoming channel session identity: {WAMPConnections.IncomingChannelSessionID}" + "\r\n\t" +
							$"- Outgoing channel session identity: {WAMPConnections.OutgoingChannelSessionID}" + "\r\n\t" +
							$"- Number of helper services: {Program.Controller.NumberOfHelperServices:#,##0}" + "\r\n\t" +
							$"- Number of scheduling timers: {Program.Controller.NumberOfTimers:#,##0}" + "\r\n\t" +
							$"- Number of scheduling tasks: {Program.Controller.NumberOfTasks:#,##0}";

						var controllers = Program.Controller.GetAvailableControllers();
						info += "\r\n" + $"All Controllers: {controllers.Count:#,##0} instance(s)";
						controllers.ForEach(controller => info += "\r\n\t" + $"- ID: {controller.ID} - Working mode: {controller.Mode} - Platform: {controller.Platform}");

						var businessServices = Program.Controller.GetAvailableBusinessServices().ToDictionary(kvp => kvp.Key, kvp => Program.Controller.GetServiceProcess(kvp.Key.ToArray('.').Last()));

						info += "\r\n" +
							$"Services:" + "\r\n\t" +
							$"- Total of available services: {businessServices.Count:#,##0}" + "\r\n\t" +
							$"- Total of running services: {businessServices.Where(kvp => kvp.Value != null).Count():#,##0}" + "\r\n\t" +
							$"Details:";
						businessServices.ForEach(kvp =>
						{
							info += "\r\n\t" + $"- URI: {kvp.Key}";
							if (kvp.Value != null)
							{
								info += $" - Unique URI: net.vieapps.services.{Extensions.GetUniqueName(kvp.Key.ToArray('.').Last(), kvp.Value.Arguments?.ToArray(' '))} - Status: Running";
								if (kvp.Value.ID != null)
									info += $" - Process ID: {kvp.Value.ID.Value}";
								if (kvp.Value.StartTime != null)
									info += $" - Serving times: {kvp.Value.StartTime.Value.GetElapsedTimes()}";
							}
							else
								info += " - Status: Stopped";
						});

						Program.Logger.LogInformation(info);
					}

					else
						showCommands();

					command = Console.ReadLine();
				}
			}

			// setup hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => Program.Stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				Program.Stop();
				Environment.Exit(0);
			};

			// start
			Program.Start(args, () =>
			{
				if (Program.IsUserInteractive)
					showCommands();
				return Task.CompletedTask;
			});

			// processing commands util got an exit signal
			if (Program.IsUserInteractive)
				processCommands();

			// wait until be killed
			else
				while (true)
					Task.Delay(54321).GetAwaiter().GetResult();

			// stop
			Program.Stop();
		}

		static void SetupEventHandlers()
		{
			if (Program.IsUserInteractive)
			{
				Global.OnProcess = (message) =>
				{
					if (!string.IsNullOrWhiteSpace(message))
						Console.WriteLine(message);
				};
				Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) => Console.Error.WriteLine(message + (exception != null ? "\r\n" + exception.StackTrace : ""));
				Global.OnSendEmailFailure = (message, exception) =>
				{
					Console.Error.WriteLine(message + (exception != null ? "\r\n" + exception.StackTrace : ""));
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
				};
				Global.OnSendWebHookFailure = (message, exception) =>
				{
					Console.Error.WriteLine(message + (exception != null ? "\r\n" + exception.StackTrace : ""));
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
				};
				Global.OnServiceStarted = Global.OnServiceStopped = Global.OnGotServiceMessage = (serviceName, message) =>
				{
					if (!string.IsNullOrWhiteSpace(message))
						Console.WriteLine($"[{serviceName.ToLower()}] => {message}");
				};
				Global.OnLogsUpdated = (serviceName, message) =>
				{
					if (!"APIGateway".IsEquals(serviceName) ? true : !message.IsContains("email message") && !message.IsContains("web-hook message"))
						Console.WriteLine($"[{serviceName.ToLower()}] => {message}");
				};
			}
			else
			{
				Global.OnProcess = (message) =>
				{
					if (!string.IsNullOrWhiteSpace(message))
						Program.Logger.LogInformation(message);
				};
				Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) => Program.Logger.LogError(message, exception);
				Global.OnSendRTUMessageSuccess = (message) =>
				{
					if (!string.IsNullOrWhiteSpace(message))
						Program.Logger.LogInformation(message);
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
						Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				};
				Global.OnLogsUpdated = (serviceName, message) =>
				{
					if (!"APIGateway".IsEquals(serviceName) ? true : !message.IsContains("email message") && !message.IsContains("web-hook message"))
						Program.Logger.LogInformation($"[{serviceName.ToLower()}] => {message}");
				};
			}
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
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));
	}
}
