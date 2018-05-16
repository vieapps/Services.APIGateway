namespace net.vieapps.Services.APIGateway
{
	partial class ServiceRunner : System.ServiceProcess.ServiceBase
	{
		public ServiceRunner()
		{
			this.InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			Program.CancellationTokenSource = new System.Threading.CancellationTokenSource();
			Program.Component = new ControlComponent(Program.CancellationTokenSource.Token);
			Program.Component.Start(args);
		}

		protected override void OnStop()
		{
			Program.Component.Dispose();
			Program.CancellationTokenSource.Cancel();
			Program.CancellationTokenSource.Dispose();
		}
	}
}
