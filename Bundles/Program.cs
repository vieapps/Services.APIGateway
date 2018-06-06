#region Related components
using System;
using System.IO;
using System.Linq;
using System.Xml;
using System.Configuration;
using System.Reflection;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args)
		{
			// prepare
			Console.OutputEncoding = System.Text.Encoding.UTF8;

			var processNodes = new List<XmlNode>();
			if (args?.FirstOrDefault(a => a.StartsWith("/config:")) != null)
			{
				var configFilePath = args.FirstOrDefault(a => a.StartsWith("/config:")).Replace(StringComparison.OrdinalIgnoreCase, "/config:", "").Trim();
				if (File.Exists(configFilePath))
					try
					{
						var xml = new XmlDocument();
						xml.LoadXml(UtilityService.ReadTextFile(configFilePath));
						processNodes = xml.DocumentElement.SelectNodes("net.vieapps.bundles/process")?.ToList();
					}
					catch { }
			}

			if (processNodes == null || processNodes.Count < 1)
				if (ConfigurationManager.GetSection("net.vieapps.bundles") is AppConfigurationSectionHandler config)
					if (config.Section.SelectNodes("./process") is XmlNodeList nodes)
						processNodes = nodes.ToList();

			if (processNodes == null || processNodes.Count < 1)
			{
				Console.Error.WriteLine("No process to run...");
				return;
			}

			var processes = new Dictionary<string, ExternalProcess.Info>();
			processNodes.Where(node => !string.IsNullOrWhiteSpace(node.Attributes["executable"]?.Value))
				.Where(node => File.Exists(node.Attributes["executable"].Value))
				.ForEach(node => processes[node.Attributes["executable"].Value] = new ExternalProcess.Info(node.Attributes["executable"].Value, node.Attributes["arguments"]?.Value ?? ""));

			void start()
			{
				Console.WriteLine($"VIEApps NGX API Gateway - Service Bundles v{Assembly.GetExecutingAssembly().GetVersion()}");
				Console.WriteLine($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
				Console.WriteLine($"Mode: {(Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null ? "Interactive app" : "Background service")}");
				Console.WriteLine($"Processes: {processes.Count:#,##0}");
				processes.Values.ToList().ForEach(info =>
				{
					processes[info.FilePath] = ExternalProcess.Start(info.FilePath, info.Arguments, (s, a) => { }, (s, a) => { });
					Console.WriteLine($"- PID: {processes[info.FilePath].ID} => {info.FilePath} {info.Arguments}");
				});
				Console.WriteLine("");
				Console.WriteLine($">>>>> Press Ctrl+C to stop all processes and terminate the bundles....");
				Console.WriteLine("");
			}

			void stop()
			{
				processes.Values.ToList().ForEach(info =>
				{
					try
					{
						ExternalProcess.Stop(info);
					}
					catch { }
				});
			}

			// setup hooks
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => stop();
			Console.CancelKeyPress += (sender, arguments) =>
			{
				stop();
				Console.WriteLine($"\r\n");
				Console.WriteLine($"Service Bundles is stopped....");
				Console.WriteLine($"\r\n");
				Environment.Exit(0);
			};

			// start and wait for exit
			start();
			while (true)
				Task.Delay(4321).GetAwaiter().GetResult();
		}
	}
}
