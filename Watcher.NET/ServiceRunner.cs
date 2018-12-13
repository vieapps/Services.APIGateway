namespace net.vieapps.Services.APIGateway
{
	public partial class ServiceRunner : System.ServiceProcess.ServiceBase
	{
		public ServiceRunner() => this.InitializeComponent();

		protected override void OnStart(string[] args) => ServiceWatcher.Start(args);

		protected override void OnStop() => ServiceWatcher.Stop();
	}
}