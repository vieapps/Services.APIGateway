using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.ServiceProcess;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services.APIGateway
{
	public static class ServiceWatcher
	{
		static ILogger Logger { get; set; } = null;
		static IDisposable Timer { get; set; } = null;
		static List<ExternalProcess.Info> Processes { get; set; } = null;

		public static void Start(string[] args)
		{
			var stopwatch = Stopwatch.StartNew();
			var isUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.IsStartsWith("/daemon")) == null;
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};
			if (isUserInteractive)
				Console.OutputEncoding = System.Text.Encoding.UTF8;

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

			Components.Utility.Logger.AssignLoggerFactory(new ServiceCollection().AddLogging(builder =>
			{
				builder.SetMinimumLevel(logLevel);
				if (isUserInteractive)
					builder.AddConsole();
			}).BuildServiceProvider().GetService<ILoggerFactory>());

			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (logPath != null && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Date}_apiwatcher.txt");
				Components.Utility.Logger.GetLoggerFactory().AddFile(logPath, logLevel);
			}
			else
				logPath = null;

			ServiceWatcher.Logger = Components.Utility.Logger.CreateLogger<Watcher>();

			var watchingProcessID = Process.GetCurrentProcess().Id;
			var watchingTime = DateTime.Now.AddMinutes(-90);
			var watchingInterval = UtilityService.GetAppSetting("Interval", "120").CastAs<int>();
			var watchingServices = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase);

			if (System.Configuration.ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler config)
				if (config.Section.SelectNodes("./service") is System.Xml.XmlNodeList services)
					services
						.ToList()
						.Where(service => !string.IsNullOrWhiteSpace(service.Attributes["name"]?.Value))
						.ForEach(service => watchingServices[service.Attributes["name"].Value] = new Tuple<string, string>(service.Attributes["beKilledFirstProcesses"]?.Value, service.Attributes["executable"]?.Value));

			void kill(string processName)
			{
				Process.GetProcessesByName(processName).ForEach(process =>
				{
					try
					{
						process.StandardInput.WriteLine("exit");
						process.StandardInput.Close();
						process.WaitForExit(789);
						process.Refresh();
						if (process.HasExited)
							ServiceWatcher.Logger.LogInformation($"Process {process.ProcessName} ({process.StartInfo.FileName}{(string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? "" : $" {process.StartInfo.Arguments}")}) has been stopped");
						else
						{
							process.Kill();
							ServiceWatcher.Logger.LogInformation($"Process {process.ProcessName} ({process.StartInfo.FileName}{(string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? "" : $" {process.StartInfo.Arguments}")}) has been stopped (killed)");
						}
					}
					catch (Exception ex)
					{
						ServiceWatcher.Logger.LogError(ex, $"Error occurred while stopping a process {process.ProcessName} ({process.StartInfo.FileName}{(string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? "" : $" {process.StartInfo.Arguments}")}) => {ex.Message}");
						try
						{
							process.Kill();
							ServiceWatcher.Logger.LogInformation($"Process {process.ProcessName} ({process.StartInfo.FileName}{(string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? "" : $" {process.StartInfo.Arguments}")}) has been stopped (killed)");
						}
						catch (Exception e)
						{
							ServiceWatcher.Logger.LogError(e, $"Error occurred while killing a process {process.ProcessName} ({process.StartInfo.FileName}{(string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? "" : $" {process.StartInfo.Arguments}")}) => {e.Message}");
						}
					}
				});
			}

			void watchWindowsService(string serviceName, string beKilledFirstProcesses)
			{
				using (var serviceController = new ServiceController(serviceName))
				{
					if (serviceController.Status.Equals(ServiceControllerStatus.Running))
					{
						if ((DateTime.Now - watchingTime).TotalMinutes > 60)
							ServiceWatcher.Logger.LogInformation($"The service \"{serviceName}\" is running normally");
					}
					else
					{
						beKilledFirstProcesses?.ToList("|").ForEach(processName => kill(processName));

						if (!serviceController.Status.Equals(ServiceControllerStatus.Stopped) && !serviceController.Status.Equals(ServiceControllerStatus.StopPending))
							serviceController.Stop();

						serviceController.Refresh();
						if (!serviceController.Status.Equals(ServiceControllerStatus.Running) && !serviceController.Status.Equals(ServiceControllerStatus.StartPending))
							serviceController.Start();

						ServiceWatcher.Logger.LogInformation($"The service \"{serviceName}\" has been restarted successfully");
					}
				}
			}

			void watchNixDaemon(string processName, string beKilledFirstProcesses, string executable)
			{
				var process = Process.GetProcesses().FirstOrDefault(p => processName.StartsWith(p.ProcessName) && p.Id != watchingProcessID);
				if (process != null)
				{
					if ((DateTime.Now - watchingTime).TotalMinutes > 60)
						ServiceWatcher.Logger.LogInformation($"The daemon \"{processName}\" [{process.ProcessName}] is running normally");
				}
				else
				{
					if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
						ServiceWatcher.Logger.LogWarning($"The daemon \"{processName}\" is not running and no executable is found");
					else
					{
						beKilledFirstProcesses?.ToList("|").ForEach(name => kill(name));
						ServiceWatcher.Processes.Add(ExternalProcess.Start(executable));
						ServiceWatcher.Logger.LogInformation($"The daemon \"{processName}\" [{executable}] has been relaunched successfully");
					}
				}
			}

			ServiceWatcher.Processes = new List<ExternalProcess.Info>();
			ServiceWatcher.Timer = System.Reactive.Linq.Observable.Timer(TimeSpan.FromSeconds(watchingInterval), TimeSpan.FromSeconds(watchingInterval)).Subscribe(_ =>
			{
				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
					watchingServices.ForEach(kvp =>
					{
						try
						{
							watchWindowsService(kvp.Key, kvp.Value.Item1);
						}
						catch (Exception ex)
						{
							ServiceWatcher.Logger.LogError($"Error occurred while watching a service ({kvp.Key}) => {ex.Message}", ex);
						}
					});
				else
					watchingServices.ForEach(kvp =>
					{
						try
						{
							watchNixDaemon(kvp.Key, kvp.Value.Item1, kvp.Value.Item2);
						}
						catch (Exception ex)
						{
							ServiceWatcher.Logger.LogError($"Error occurred while watching a daemon ({kvp.Key}) => {ex.Message}", ex);
						}
					});

				if ((DateTime.Now - watchingTime).TotalMinutes > 60)
					watchingTime = DateTime.Now;
			});

			ServiceWatcher.Logger.LogInformation($"Starting");
			ServiceWatcher.Logger.LogInformation($"Version: VIEApps NGX API Watcher {typeof(Watcher).Assembly.GetVersion()}");
			ServiceWatcher.Logger.LogInformation($"Mode: {(isUserInteractive ? "Interactive app" : "Background service")}");
			ServiceWatcher.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
			ServiceWatcher.Logger.LogInformation($"Root path (base directory): {AppDomain.CurrentDomain.BaseDirectory}");
			ServiceWatcher.Logger.LogInformation($"Logging level: {logLevel} - Rolling log files is {(logPath == null ? "disabled" : $"enabled => {logPath}")}");
			ServiceWatcher.Logger.LogInformation($"Watching interval: {watchingInterval} seconds - {watchingServices.Count} service(s) being watched => {watchingServices.Keys.ToString(", ")}");

			stopwatch.Stop();
			ServiceWatcher.Logger.LogInformation($"Started - PID: {watchingProcessID} - Execution times: {stopwatch.GetElapsedTimes()}");
		}

		public static void Stop()
		{
			ServiceWatcher.Logger.LogInformation(ServiceWatcher.Processes != null ? "Stopped" : "Disposed");
			ServiceWatcher.Timer?.Dispose();
			ServiceWatcher.Timer = null;
			ServiceWatcher.Processes?.ForEach(process => ExternalProcess.Stop(process));
			ServiceWatcher.Processes = null;
		}
	}

	class Watcher { }
}