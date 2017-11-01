using System;
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

			// run as a service of Windows
			if (Global.AsService)
			{
				System.IO.Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
				System.ServiceProcess.ServiceBase.Run(new ServiceRunner());
			}

			// run as a desktop app of Windows
			else
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);

				Global.Form = new MainForm(args);
				Application.Run(Global.Form);
			}
		}
	}
}