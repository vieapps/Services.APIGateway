﻿namespace net.vieapps.Services.APIGateway
{
	partial class ServiceRunner : System.ServiceProcess.ServiceBase
	{
		public ServiceRunner()
		{
			this.InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			Global.InitializeLog();
			Global.Component.Start(args);
		}

		protected override void OnStop()
		{
			Global.Component.Dispose();
			Global.DisposeLog();
		}
	}
}