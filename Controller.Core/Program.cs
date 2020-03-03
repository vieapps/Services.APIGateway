#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
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
		static CancellationTokenSource CancellationTokenSource { get; set; }
		static ILoggingService LoggingService { get; set; }
		static Manager Manager { get; set; }
		static Controller Controller { get; set; }
		static ILogger Logger { get; set; }
		static bool IsUserInteractive { get; set; }
		static bool IsStopped { get; set; } = false;
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

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder =>
			{
				builder.SetMinimumLevel(logLevel);
				if (Program.IsUserInteractive)
					builder.AddConsole();
			}).BuildServiceProvider().GetService<ILoggerFactory>());

			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (logPath != null && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}_apigateway.controller.txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

			Program.Logger = Components.Utility.Logger.CreateLogger<Controller>();

			// prepare event handlers
			Program.SetupEventHandlers();

			// prepare hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => 
			{
				if (!Program.IsStopped)
				{
					Program.Logger.LogWarning(">>> Terminated by signal of process exit");
					try
					{
						Program.Stop();
					}
					catch { }
				}
			};

			Console.CancelKeyPress += (sender, arguments) =>
			{
				Program.Logger.LogWarning(">>> Terminated by signal of cancel key press");
				try
				{
					Program.Stop();
				}
				catch { }
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
						var controllerID = commands.Length > 1 ? commands[1].ToLower() : "local";
						if (controllerID.IsEquals("global"))
						{
							var controllers = Program.Manager.AvailableControllers;
							var info = $"Controllers - Total instance(s): {Program.Manager.AvailableControllers.Count:#,##0} - Available instance(s): {Program.Manager.AvailableControllers.Where(kvp => kvp.Value.Available).Count():#,##0}";
							Program.Manager.AvailableControllers.ForEach(controller => info += "\r\n\t" + $"- ID: {controller.ID} - Status: {(controller.Available ? "Available" : "Unavailable")} - Working mode: {controller.Mode} - Platform: {controller.Platform}");
							info += "\r\n" + $"Services - Total: {Program.Manager.AvailableServices.Count:#,##0} - Available: {Program.Manager.AvailableServices.Where(kvp => kvp.Value.FirstOrDefault(svc => svc.Available) != null).Count():#,##0} - Running: {Program.Manager.AvailableServices.Where(kvp => kvp.Value.FirstOrDefault(svc => svc.Running) != null).Count():#,##0}";
							Program.Manager.AvailableServices.OrderBy(kvp => kvp.Key).ForEach(kvp => info += "\r\n\t" + $"- URI: services.{kvp.Key} - Available instance(s): {kvp.Value.Where(svc => svc.Available).Count():#,##0} - Running instance(s): {kvp.Value.Where(svc => svc.Running).Count():#,##0}");
							Program.Logger.LogInformation(info);
						}
						else if (controllerID.IsEquals("local") || controllerID.IsEquals(Program.Controller.Info.ID))
						{
							var info =
								$"Controller:" + "\r\n\t" +
								$"- Version: {Assembly.GetExecutingAssembly().GetVersion()}" + "\r\n\t" +
								$"- Working mode: {(Environment.UserInteractive ? "Interactive app" : "Background service")}" + "\r\n\t" +
								$"- Environment:\r\n\t\t{Extensions.GetRuntimeEnvironment("\r\n\t\t")}" + "\r\n\t" +
								$"- API Gateway Router: {new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}" + "\r\n\t" +
								$"- Incoming channel session identity: {Router.IncomingChannelSessionID}" + "\r\n\t" +
								$"- Outgoing channel session identity: {Router.OutgoingChannelSessionID}" + "\r\n\t" +
								$"- Number of helper services: {Program.Controller.NumberOfHelperServices:#,##0}" + "\r\n\t" +
								$"- Number of scheduling timers: {Program.Controller.NumberOfTimers:#,##0}" + "\r\n\t" +
								$"- Number of scheduling tasks: {Program.Controller.NumberOfTasks:#,##0}";
							var services = Program.Controller.AvailableBusinessServices.OrderBy(kvp => kvp.Key).ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Instance);
							info += "\r\n" + $"Services - Available: {services.Count:#,##0} - Running: {services.Where(kvp => kvp.Value != null).Count():#,##0}";
							services.ForEach(kvp =>
							{
								info += "\r\n\t" + $"- URI: services.{kvp.Key}";
								if (kvp.Value != null)
								{
									var svcArgs = kvp.Value.Arguments?.ToArray(' ') ?? new string[] { };
									info += $" (services.{Extensions.GetUniqueName(kvp.Key.ToArray('.').Last(), svcArgs)}) - Status: Running";
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
								info += "\r\n\t" + $"- URI: services.{svc.Name} ({svc.UniqueName}) - Status: {(svc.Running ? "Running" : "Stopped")}";
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
								? commands[2].ToLower()
								: Program.Controller.Info.ID;
							if (!Program.Manager.AvailableControllers.ContainsKey(controllerID))
								Program.Logger.LogWarning($"Controller with identity \"{controllerID}\" is not found");
							else
								Program.Manager.StartBusinessService(controllerID, commands[1].ToLower(), Program.Controller.GetServiceArguments().Replace("/", "/call-"));
						}
						else
							Program.Logger.LogInformation($"Invalid {command} command");
					}

					else if (commands[0].IsEquals("stop"))
					{
						if (commands.Length > 1)
						{
							var controllerID = commands.Length > 2
								? commands[2].ToLower()
								: Program.Controller.Info.ID;
							if (!Program.Manager.AvailableControllers.ContainsKey(controllerID))
								Program.Logger.LogWarning($"Controller with identity \"{controllerID}\" is not found");
							else
								Program.Manager.StopBusinessService(controllerID, commands[1].ToLower());
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

					else if (!commands[0].IsEquals("exit"))
						Program.Logger.LogInformation(
							"Commands:" + "\r\n\t" +
							"info [global | controller-id]: show the information of controllers & services" + "\r\n\t" +
							"start <name> [controller-id]: start a business service" + "\r\n\t" +
							"stop <name> [controller-id]: stop a business service" + "\r\n\t" +
							"refresh: refresh the information of controllers & services" + "\r\n\t" +
							"help: show available commands" + "\r\n\t" +
							"exit: shutdown & terminate"
						);

					command = commands[0].IsEquals("exit")
						? null
						: Console.ReadLine();
				}
			}

			// wait until be killed
			else
				while (true)
					Task.Delay(54321).GetAwaiter().GetResult();

			// stop and do clean up
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
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "Emails", message)).ConfigureAwait(false);
				}
			};

			Global.OnSendWebHookSuccess = (message) =>
			{
				if (!string.IsNullOrWhiteSpace(message))
				{
					Program.Logger.LogInformation(message);
					Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "WebHooks", message)).ConfigureAwait(false);
				}
			};

			Global.OnSendEmailFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "Emails", message, exception.GetStack())).ConfigureAwait(false);
			};

			Global.OnSendWebHookFailure = (message, exception) =>
			{
				Program.Logger.LogError(message, exception);
				Task.Run(() => Program.GetLoggingService()?.WriteLogAsync(UtilityService.NewUUID, null, null, "APIGateway", "WebHooks", message, exception.GetStack())).ConfigureAwait(false);
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

		static void Start(string[] args, Action<Controller> next = null)
		{
			Program.CancellationTokenSource = new CancellationTokenSource();
			Program.Manager = new Manager();
			Program.Controller = new Controller(Program.CancellationTokenSource.Token);
			Program.Controller.Start(args, Program.Manager.OnIncomingConnectionEstablished, Program.Manager.OnOutgoingConnectionEstablished, next);
		}

		static async Task StopAsync()
		{
			await Task.WhenAll(Program.Manager.DisposeAsync(), Program.Controller.DisposeAsync()).ConfigureAwait(false);
			Program.IsStopped = true;
			Program.CancellationTokenSource.Cancel();
			Program.CancellationTokenSource.Dispose();
			Program.Logger.LogInformation($"The API Gateway Controller was terminated");
			await Task.Delay(123).ConfigureAwait(false);
		}

		static void Stop()
			=> Task.Run(async () => await(Program.IsStopped? Task.CompletedTask : Program.StopAsync()).ConfigureAwait(false)).ConfigureAwait(false).GetAwaiter().GetResult();

		static ILoggingService GetLoggingService()
			=> Program.LoggingService ?? (Program.LoggingService = Router.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create()));
	}
}
