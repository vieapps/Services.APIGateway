using System;
using System.IO;
using System.ServiceProcess;
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

			// run as Windows service
			if (Global.AsService)
			{
				Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
				ServiceBase.Run(new ServiceRunner());
			}

			// run as Windows app
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