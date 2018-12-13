namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main() => System.ServiceProcess.ServiceBase.Run(new[] { new ServiceRunner() });
	}
}