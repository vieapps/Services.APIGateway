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
		internal static IController ServiceManager { get; set; } = null;
		internal static ILoggingService LoggingService { get; set; } = null;
		internal static Manager Manager { get; set; } = null;
		internal static Controller Controller { get; set; } = null;
		internal static ILogger Logger { get; set; }
		internal static bool IsUserInteractive { get; set; } = false;
		#endregion

		static void Main(string[] args)
		{
			// prepare environment
			Program.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.IsStartsWith("/daemon")) == null;
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
			Console.OutputEncoding = System.Text.Encoding.UTF8;
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
				logLevel = (args?.FirstOrDefault(a => a.IsStartsWith("/loglevel:"))?.Replace(StringComparison.OrdinalIgnoreCase, "/loglevel:", "") ?? UtilityService.GetAppSetting("Logs:Level", "Information")).ToEnum<LogLevel>();
			}
			catch { }
#endif

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder =>
			{
				builder.SetMinimumLevel(logLevel);
				if (Program.IsUserInteractive)
					builder.AddConsole();
			}).BuildServiceProvider().GetService<ILoggerFactory>());

			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (logPath != null && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Date}_apigateway.controller.txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

			Program.Logger = Components.Utility.Logger.CreateLogger<Controller>();

			// prepare event handlers
			Program.SetupEventHandlers();

			// prepare hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => Program.Stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				Program.Stop();
				Environment.Exit(0);
			};

			// start
			Program.Start(args);

			// processing commands util got an exit signal (not available when running in Docker)
			if (Program.IsUserInteractive && args?.FirstOrDefault(a => a.IsStartsWith("/docker")) == null)
			{
				var command = Console.ReadLine();
				while (command != null)
				{
					var commands = command.ToArray(' ');

					if (commands[0].IsEquals("info"))
					{
						var controllerID = commands.Length > 1 ? commands[1].ToLower().Trim() : "local";
						if (controllerID.IsEquals("global"))
						{
							var controllers = Program.Manager.AvailableControllers;
							var info = $"Controllers - Total instance(s): {Program.Manager.AvailableControllers.Count:#,##0} - Available instance(s): {Program.Manager.AvailableControllers.Where(kvp => kvp.Value.Available).Count():#,##0}";
							Program.Manager.AvailableControllers.ForEach(controller => info += "\r\n\t" + $"- ID: {controller.ID} - Status: {(controller.Available ? "Available" : "Unavailable")}  - Working mode: {controller.Mode} - Platform: {controller.Platform}");
							info += "\r\n" + $"Services - Total: {Program.Manager.AvailableServices.Count:#,##0} - Available: {Program.Manager.AvailableServices.Where(kvp => kvp.Value.FirstOrDefault(svc => svc.Available) != null).Count():#,##0} - Running: {Program.Manager.AvailableServices.Where(kvp => kvp.Value.FirstOrDefault(svc => svc.Running) != null).Count():#,##0}";
							Program.Manager.AvailableServices.OrderBy(kvp => kvp.Key).ForEach(kvp => info += "\r\n\t" + $"- URI: net.vieapps.services.{kvp.Key} - Available instance(s): {kvp.Value.Where(svc => svc.Available).Count():#,##0} - Running instance(s): {kvp.Value.Where(svc => svc.Running).Count():#,##0}");
							Program.Logger.LogInformation(info);
						}
						else if (controllerID.IsEquals("local") || controllerID.IsEquals(Program.Controller.Info.ID))
						{
							var info =
								$"Controller:" + "\r\n\t" +
								$"- Version: {typeof(Controller).Assembly.GetVersion()}" + "\r\n\t" +
								$"- Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})" + "\r\n\t" +
								$"- Working mode: {(Environment.UserInteractive ? "Interactive app" : "Background service")}" + "\r\n\t" +
								$"- WAMP router: {new Uri(WAMPConnections.GetRouterStrInfo()).GetResolvedURI()}" + "\r\n\t" +
								$"- Incoming channel session identity: {WAMPConnections.IncomingChannelSessionID}" + "\r\n\t" +
								$"- Outgoing channel session identity: {WAMPConnections.OutgoingChannelSessionID}" + "\r\n\t" +
								$"- Number of helper services: {Program.Controller.NumberOfHelperServices:#,##0}" + "\r\n\t" +
								$"- Number of scheduling timers: {Program.Controller.NumberOfTimers:#,##0}" + "\r\n\t" +
								$"- Number of scheduling tasks: {Program.Controller.NumberOfTasks:#,##0}";
							var services = Program.Controller.GetAvailableBusinessServices().OrderBy(kvp => kvp.Key).ToDictionary(kvp => kvp.Key, kvp => Program.Controller.GetServiceProcess(kvp.Key.ToArray('.').Last()));
							info += "\r\n" + $"Services - Available: {services.Count:#,##0} - Running: {services.Where(kvp => kvp.Value != null).Count():#,##0}";
							services.ForEach(kvp =>
							{
								info += "\r\n\t" + $"- URI: {kvp.Key}";
								if (kvp.Value != null)
								{
									var svcArgs = kvp.Value.Arguments?.ToArray(' ') ?? new string[] { };
									info += $" ({Extensions.GetUniqueName(kvp.Key.ToArray('.').Last(), svcArgs)}) - Status: Running";
									if (kvp.Value.ID != null)
										info += $" - Process ID: {kvp.Value.ID.Value}";
									if (kvp.Value.StartTime != null)
										info += $" - Serving times: {kvp.Value.StartTime.Value.GetElapsedTimes()}";
									var user = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-user:"));
									if (!string.IsNullOrWhiteSpace(user))
									{
										info += $" - Invoked by: {user.Replace(StringComparison.OrdinalIgnoreCase, "/call-user:", "").UrlDecode()}";
										var host = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-host:"));
										var platform = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-platform:"));
										var os = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-os:"));
										if (!string.IsNullOrWhiteSpace(host) && !string.IsNullOrWhiteSpace(platform) && !string.IsNullOrWhiteSpace(os))
											info += $" [Host: {host.Replace(StringComparison.OrdinalIgnoreCase, "/call-host:", "").UrlDecode()} - Platform: {platform.Replace(StringComparison.OrdinalIgnoreCase, "/call-platform:", "").UrlDecode()} @ {os.Replace(StringComparison.OrdinalIgnoreCase, "/call-os:", "").UrlDecode()}]";
									}
								}
								else
									info += " - Status: Stopped";
							});
							Program.Logger.LogInformation(info);
						}
						else if (Program.Manager.AvailableControllers.ContainsKey(controllerID))
						{
							var controller = Program.Manager.AvailableControllers[controllerID];
							var info =
								$"Controller:" + "\r\n\t" +
								$"- ID: {controller.ID}" + "\r\n\t" +
								$"- Platform: {controller.Platform})" + "\r\n\t" +
								$"- Working mode: {controller.Mode}" + "\r\n\t" +
								$"- Host: {controller.Host}" + "\r\n\t" +
								$"- User: {controller.User}" + "\r\n\t" +
								$"- Status: {(controller.Available ? "Available" : "Unvailable")}" + "\r\n\t";
							info += controller.Available
								? $"- Starting time: {controller.Timestamp.ToDTString()} [Served times: {controller.Timestamp.GetElapsedTimes()}]"
								: $"- Last working time: {controller.Timestamp.ToDTString()}";
							var services = Program.Manager.AvailableServices.Values.Select(svc => svc.FirstOrDefault(svcInfo => svcInfo.ControllerID.Equals(controller.ID))).Where(svcInfo => svcInfo != null).OrderBy(svcInfo => svcInfo.Name).ToList();
							info += "\r\n" + $"Services - Available: {services.Where(svc => svc.Available).Count():#,##0} - Running: {services.Where(svc => svc.Running).Count():#,##0}";
							services.ForEach(svc =>
							{
								info += "\r\n\t" + $"- URI: net.vieapps.services.{svc.Name} ({svc.UniqueName}) - Status: {(svc.Running ? "Running" : "Stopped")}";
								info += svc.Running
									? $" - Starting time: {svc.Timestamp.ToDTString()} [Served times: {svc.Timestamp.GetElapsedTimes()}] - Invoked by: {svc.InvokeInfo}"
									: $" - Last working time: {svc.Timestamp.ToDTString()}";
							});
							Program.Logger.LogInformation(info);
						}
						else
							Program.Logger.LogWarning($"Controller with identity \"{controllerID}\" is not found");
					}

					else if (commands[0].IsEquals("start"))
					{
						if (commands.Length > 1)
						{
							var controllerID = commands.Length > 2
								? commands[2].ToLower().Trim()
								: Program.Controller.Info.ID;
							if (!Program.Manager.AvailableControllers.ContainsKey(controllerID))
								Program.Logger.LogWarning($"Controller with identity \"{controllerID}\" is not found");
							else
								Program.Manager.StartBusinessService(controllerID, commands[1], Program.Controller.GetServiceArguments().Replace("/", "/call-"));
						}
						else
							Program.Logger.LogInformation($"Invalid {command} command");
					}

					else if (commands[0].IsEquals("stop"))
					{
						if (commands.Length > 1)
						{
							var controllerID = commands.Length > 2
								? commands[2].ToLower().Trim()
								: Program.Controller.Info.ID;
							if (!Program.Manager.AvailableControllers.ContainsKey(controllerID))
								Program.Logger.LogWarning($"Controller with identity \"{controllerID}\" is not found");
							else
								Program.Manager.StopBusinessService(controllerID, commands[1]);
						}
						else
							Program.Logger.LogInformation($"Invalid {command} command");
					}

					else if (commands[0].IsEquals("refresh"))
						Task.Run(async () =>
						{
							await Program.Manager.SendInterCommunicateMessageAsync("Controller#RequestInfo").ConfigureAwait(false);
							await Program.Manager.SendInterCommunicateMessageAsync("Service#RequestInfo").ConfigureAwait(false);
						}).ConfigureAwait(false);

					else if (commands[0].IsEquals("exit"))
						return;

					else
						Program.Logger.LogInformation(
							"VIEApps NGX Services Controller commands:" + "\r\n\t" +
							"info [global | controller-id]: show the information of controllers & services" + "\r\n\t" +
							"start <name> [controller-id]: start a business service" + "\r\n\t" +
							"stop <name> [controller-id]: stop a business service" + "\r\n\t" +
							"refresh: refresh the information of controllers & services" + "\r\n\t" +
							"help: show available commands" + "\r\n\t" +
							"exit: shutdown & terminate"
						);

					command = Console.ReadLine();
				}
			}
				
			// wait until be killed
			else
				while (true)
					Task.Delay(54321).GetAwaiter().GetResult();

			// stop
			Program.Stop();
		}

		static void SetupEventHandlers()
		{
			Global.OnProcess = (message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
					Program.Logger.LogInformation(message);
			};

			Global.OnError = Global.OnSendRTUMessageFailure = (message, exception) => Program.Logger.LogError(message, exception);

			Global.OnSendRTUMessageSuccess = (message) =>
			{
				if (Program.Logger.IsEnabled(LogLevel.Debug) && !string.IsNullOrWhiteSpace(message))
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

		internal static void Start(string[] args, Func<Task> nextAsync = null)
		{
			Program.CancellationTokenSource = new CancellationTokenSource();
			Program.Manager = new Manager();
			Program.Controller = new Controller(Program.CancellationTokenSource.Token);
			Program.Controller.Start(args, Program.Manager.OnIncomingChannelEstablished, Program.Manager.OnOutgoingChannelEstablished, nextAsync);
		}

		internal static void Stop()
		{
			Program.Manager.Dispose();
			Program.Controller.Dispose();
			Program.CancellationTokenSource.Cancel();
		}

		internal static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = WAMPConnections.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));
	}
}
