namespace net.vieapps.Services.APIGateway
{
	partial class ServiceRunner : System.ServiceProcess.ServiceBase
	{
		public ServiceRunner() => this.InitializeComponent();

		protected override void OnStart(string[] args) => Program.Start();

		protected override void OnStop() => Program.Stop();
	}
}
