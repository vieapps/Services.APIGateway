#region Related components
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.ServiceProcess;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Watcher { }

	public static class ServiceWatcher
	{

		#region Properties
		static ILogger Logger { get; set; }

		static IDisposable Timer { get; set; }

		static bool WatchingFlag { get; set; } = false;

		static List<ExternalProcess.Info> WatchingProcesses { get; set; }

		static int WatchingProcessID { get; set; }

		static DateTime WatchingTime { get; set; } = DateTime.Now.AddMinutes(-90);
		
		static int WatchingInterval { get; set; } = UtilityService.GetAppSetting("TimerInterval:Watcher", "35").CastAs<int>();

		static ConcurrentDictionary<string, Tuple<string, string, DateTime?>> WatchingServices { get; } = new ConcurrentDictionary<string, Tuple<string, string, DateTime?>>(StringComparer.OrdinalIgnoreCase);

		static List<Tuple<string, string, string>>  WatchingInfo { get; set; }

		static HashSet<string> RecyclingServices { get; set; } = UtilityService.GetAppSetting("RecyclingServices", "").ToHashSet("|", true);
		#endregion

		public static void Start(string[] args, Action onCompleted = null)
		{
			var stopwatch = Stopwatch.StartNew();
			var isUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(arg => arg.IsStartsWith("/daemon")) == null;
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
			ServiceWatcher.WatchingProcessID = Process.GetCurrentProcess().Id;
			ServiceWatcher.WatchingProcesses = new List<ExternalProcess.Info>();

			if (System.Configuration.ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Services", "net.vieapps.services")) is AppConfigurationSectionHandler config)
				if (config.Section.SelectNodes("./service") is System.Xml.XmlNodeList services)
					services
						.ToList()
						.Where(service => !string.IsNullOrWhiteSpace(service.Attributes["name"]?.Value))
						.ForEach(service => ServiceWatcher.WatchingServices[service.Attributes["name"].Value] = new Tuple<string, string, DateTime?>(service.Attributes["beKilledFirstProcesses"]?.Value, service.Attributes["executable"]?.Value, null));

			ServiceWatcher.WatchingInfo = ServiceWatcher.WatchingServices.Select(kvp => new Tuple<string, string, string>(kvp.Key, kvp.Value.Item1, kvp.Value.Item2)).ToList();
			ServiceWatcher.Timer = System.Reactive.Linq.Observable.Timer(TimeSpan.FromSeconds(ServiceWatcher.WatchingInterval), TimeSpan.FromSeconds(ServiceWatcher.WatchingInterval)).Subscribe(_ =>
			{
				if (!ServiceWatcher.WatchingFlag)
				{
					ServiceWatcher.WatchingFlag = true;
					if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						ServiceWatcher.WatchingInfo.ForEach(info =>
						{
							try
							{
								ServiceWatcher.WatchService(info.Item1, info.Item2);
							}
							catch (Exception ex)
							{
								ServiceWatcher.Logger.LogError($"Error occurred while watching a service ({info.Item1}) => {ex.Message}", ex);
							}
						});
					else
						ServiceWatcher.WatchingInfo.ForEach(info =>
						{
							try
							{
								ServiceWatcher.WatchDaemon(info.Item1, info.Item2, info.Item3);
							}
							catch (Exception ex)
							{
								ServiceWatcher.Logger.LogError($"Error occurred while watching a daemon ({info.Item1}) => {ex.Message}", ex);
							}
						});

					ServiceWatcher.WatchingFlag = false;
					if ((DateTime.Now - ServiceWatcher.WatchingTime).TotalMinutes > 60)
						ServiceWatcher.WatchingTime = DateTime.Now;
				}
			});

			ServiceWatcher.Logger.LogInformation($"VIEApps NGX API Watcher is starting");
			ServiceWatcher.Logger.LogInformation($"Version: {typeof(Watcher).Assembly.GetVersion()}");
			ServiceWatcher.Logger.LogInformation($"Mode: {(isUserInteractive ? "Interactive app" : "Background service")}");
			ServiceWatcher.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
			ServiceWatcher.Logger.LogInformation($"Root (base) directory: {AppDomain.CurrentDomain.BaseDirectory}");
			ServiceWatcher.Logger.LogInformation($"Logging level: {logLevel} - Local rolling log files is {(logPath == null ? "disabled" : $"enabled => {logPath}")}");
			ServiceWatcher.Logger.LogInformation($"Watching interval: {ServiceWatcher.WatchingInterval} seconds - {ServiceWatcher.WatchingServices.Count} service(s) being watched => {ServiceWatcher.WatchingServices.Keys.ToString(", ")}");

			stopwatch.Stop();
			ServiceWatcher.Logger.LogInformation($"Started - PID: {ServiceWatcher.WatchingProcessID} - Execution times: {stopwatch.GetElapsedTimes()}");

			var restart = args?.FirstOrDefault(arg => arg.IsStartsWith("/restart:"));
			if (!string.IsNullOrWhiteSpace(restart))
			{
				restart = restart.Replace("/restart:", "");
				try
				{
					ServiceWatcher.RestartService(restart);
				}
				catch (Exception ex)
				{
					ServiceWatcher.Logger.LogError($"Error occurred while restarting a service ({restart}) => {ex.Message}", ex);
				}
			}

			onCompleted?.Invoke();
		}

		public static void Stop(Action onCompleted = null)
		{
			ServiceWatcher.Logger.LogInformation(ServiceWatcher.WatchingProcesses != null ? "Stopped" : "Disposed");
			ServiceWatcher.Timer?.Dispose();
			ServiceWatcher.Timer = null;
			ServiceWatcher.WatchingProcesses?.ForEach(process => ExternalProcess.Stop(process));
			ServiceWatcher.WatchingProcesses = null;
			onCompleted?.Invoke();
		}

		static void Kill(string processName)
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

		static void RestartService(ServiceController serviceController, string beKilledFirstProcesses = null)
		{
			beKilledFirstProcesses?.ToList("|").ForEach(processName => ServiceWatcher.Kill(processName));

			if (!serviceController.Status.Equals(ServiceControllerStatus.Stopped) && !serviceController.Status.Equals(ServiceControllerStatus.StopPending))
				try
				{
					serviceController.Stop();
					serviceController.Refresh();
					ServiceWatcher.Logger.LogInformation($"The service \"{serviceController.ServiceName}\" was stopped");
				}
				catch (Exception ex)
				{
					ServiceWatcher.Logger.LogError($"Error occurred while stopping a service ({serviceController.ServiceName} [{serviceController.Status}]) => {ex.Message}", ex);
				}

			serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(6789));
			serviceController.Refresh();

			if (!serviceController.Status.Equals(ServiceControllerStatus.Running) && !serviceController.Status.Equals(ServiceControllerStatus.StartPending))
				try
				{
					serviceController.Start();
					ServiceWatcher.Logger.LogInformation($"The service \"{serviceController.ServiceName}\" was restarted");
				}
				catch (Exception ex)
				{
					ServiceWatcher.Logger.LogError($"Error occurred while restarting a service ({serviceController.ServiceName} [{serviceController.Status}]) => {ex.Message}", ex);
				}

			ServiceWatcher.WatchingServices[serviceController.ServiceName] = ServiceWatcher.WatchingServices.TryGetValue(serviceController.ServiceName, out var info)
				? new Tuple<string, string, DateTime?>(info?.Item1, info?.Item2, DateTime.Now)
				: new Tuple<string, string, DateTime?>(null, null, DateTime.Now);
		}

		static void RestartService(string serviceName, string beKilledFirstProcesses = null)
		{
			using (var serviceController = new ServiceController(serviceName))
				ServiceWatcher.RestartService(serviceController, beKilledFirstProcesses);
		}

		static void WatchService(string serviceName, string beKilledFirstProcesses)
		{
			using (var serviceController = new ServiceController(serviceName))
			{
				var needRestart = false;
				if (serviceController.Status.Equals(ServiceControllerStatus.Running))
				{
					if ((DateTime.Now - ServiceWatcher.WatchingTime).TotalMinutes > 60)
						ServiceWatcher.Logger.LogInformation($"The service \"{serviceName}\" is running normally");

					if (ServiceWatcher.WatchingServices.TryGetValue(serviceName, out var info))
					{
						if (info.Item3 == null)
							ServiceWatcher.WatchingServices[serviceName] = new Tuple<string, string, DateTime?>(info.Item1, info.Item2, DateTime.Now);
						else if (ServiceWatcher.RecyclingServices.Contains(serviceName) && DateTime.Now.Hour == 3 && (DateTime.Now - info.Item3.Value).Hours > 6)
							needRestart = true;
					}
				}
				else
					needRestart = true;

				if (needRestart)
					ServiceWatcher.RestartService(serviceController, beKilledFirstProcesses);
			}
		}

		static void WatchDaemon(string processName, string beKilledFirstProcesses, string executable)
		{
			var process = Process.GetProcesses().FirstOrDefault(p => processName.StartsWith(p.ProcessName) && p.Id != ServiceWatcher.WatchingProcessID);
			if (process != null)
			{
				if ((DateTime.Now - ServiceWatcher.WatchingTime).TotalMinutes > 60)
					ServiceWatcher.Logger.LogInformation($"The daemon \"{processName}\" [{process.ProcessName}] is running normally");
			}
			else
			{
				if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
					ServiceWatcher.Logger.LogWarning($"The daemon \"{processName}\" is not running and no executable is found");
				else
				{
					beKilledFirstProcesses?.ToList("|").ForEach(name => ServiceWatcher.Kill(name));
					ServiceWatcher.WatchingProcesses.Add(ExternalProcess.Start(executable));
					ServiceWatcher.Logger.LogInformation($"The daemon \"{processName}\" [{executable}] has been relaunched successfully");
				}
			}
		}
	}
}