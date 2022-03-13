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
			var services = new Dictionary<string, ExternalProcess.Info>();
			var svcNodes = new List<XmlNode>();

			if (args?.FirstOrDefault(a => a.StartsWith("/config:")) != null)
			{
				var configFilePath = args.FirstOrDefault(a => a.StartsWith("/config:")).Replace(StringComparison.OrdinalIgnoreCase, "/config:", "").Trim();
				if (File.Exists(configFilePath))
					try
					{
						var xml = new XmlDocument();
						xml.LoadXml(new FileInfo(configFilePath).ReadAsText());
						svcNodes = xml.DocumentElement.SelectNodes("net.vieapps.services.bundles/service")?.ToList();
					}
					catch { }
			}

			if (svcNodes == null || svcNodes.Count < 1)
				if (ConfigurationManager.GetSection("net.vieapps.services.bundles") is AppConfigurationSectionHandler config)
					if (config.Section.SelectNodes("./service") is XmlNodeList nodes)
						svcNodes = nodes.ToList();

			svcNodes?.Where(svcNode => !string.IsNullOrWhiteSpace(svcNode.Attributes["executable"]?.Value) && File.Exists(svcNode.Attributes["executable"].Value + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !svcNode.Attributes["executable"].Value.IsEndsWith(".exe") ? ".exe" : ""))).ForEach(svcNode =>
			{
				var svcInfo = new ExternalProcess.Info(svcNode.Attributes["executable"].Value, svcNode.Attributes["arguments"]?.Value ?? "");
				svcInfo.Extra["waitingTimes"] = Int32.TryParse(svcNode.Attributes["waitingTimes"]?.Value, out int waitingTimes) ? waitingTimes : 0;
				services[svcNode.Attributes["executable"].Value] = svcInfo;
			});

			if (services.Count < 1)
			{
				Console.Error.WriteLine("No service to run...");
				return;
			}

			void start()
			{
				Console.WriteLine($"VIEApps NGX API Gateway - Service Bundles {Assembly.GetExecutingAssembly().GetVersion()}");
				Console.WriteLine($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
				Console.WriteLine($"Mode: {(Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null ? "Interactive app" : "Background service")}");
				Console.WriteLine($"Services: {services.Count:#,##0}");
				services.Keys.ToList().ForEach(executable =>
				{
					var svcInfo = services[executable];
					if (svcInfo.Extra.TryGetValue("waitingTimes", out object waitingTimes) && (int)waitingTimes > 0)
						Task.Delay((int)waitingTimes).GetAwaiter().GetResult();
					svcInfo = services[executable] = ExternalProcess.Start(svcInfo.FilePath, svcInfo.Arguments, (s, a) => { }, (s, a) => { });
					Console.WriteLine($"- PID: {svcInfo.ID} => {svcInfo.FilePath} {svcInfo.Arguments}");
				});
				Console.WriteLine("");
				Console.WriteLine($">>>>> Press Ctrl+C to stop all processes and terminate the bundles....");
				Console.WriteLine("");
			}

			void stop()
			{
				services.Values.ToList().ForEach(info =>
				{
					try
					{
						ExternalProcess.Stop(info);
					}
					catch { }
				});
			}

			// setup environment
			AppDomain.CurrentDomain.ProcessExit += (sender, arguments) => stop();
			Console.OutputEncoding = System.Text.Encoding.UTF8;
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
				Task.Delay(54321).GetAwaiter().GetResult();
		}
	}
}