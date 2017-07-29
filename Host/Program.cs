using System;
using System.ServiceProcess;
using System.Windows.Forms;

namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		[STAThread]
		static void Main()
		{
			// initialize
			Global.AsService = !Environment.UserInteractive;
			Global.Component = new ServiceComponent();

			// run as Windows service
			if (Global.AsService)
				ServiceBase.Run(new ServiceRunner());

			// run as desktop app
			else
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);
				Global.Form = new MainForm();
				Application.Run(Global.Form);
			}
		}
	}
}