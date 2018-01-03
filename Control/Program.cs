using System;
using System.IO;
using System.Windows.Forms;

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		[STAThread]
		static void Main(string[] args)
		{
			// initialize
			Global.AsService = !Environment.UserInteractive;
			Global.Component = new ServiceComponent();
			Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

			// run as a Windows service
			if (Global.AsService)
				System.ServiceProcess.ServiceBase.Run(new ServiceRunner());

			// run as a Windows desktop app
			else
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);

				Global.MainForm = new MainForm(args);
				Application.Run(Global.MainForm);
			}
		}
	}
}