using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyModel;
using Microsoft.Extensions.DependencyModel.Resolution;
namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHost
	{
		protected override void PrepareServiceType()
		{
			base.PrepareServiceType();
			if (this.ServiceType == null)
			{
				var path = AppDomain.CurrentDomain.BaseDirectory;
				var assembly = AssemblyLoader.LoadFromAssemblyPath(Path.Combine(path, $"{this.ServiceAssemblyName}.dll"));
				if (!File.Exists(Path.Combine(path, $"{this.ServiceAssemblyName}.deps.json")))
					assembly.GetReferencedAssemblies().ToList().ForEach(n => AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(path, $"{n.Name}.dll")));
				this.ServiceType = assembly.GetExportedTypes().FirstOrDefault(serviceType => this.ServiceTypeName.Equals(serviceType.ToString()));
			}
		}
	}

	class AssemblyLoader
	{
		public static Assembly LoadFromAssemblyPath(string assemblyPath)
			=> File.Exists(Path.Combine(Path.GetDirectoryName(assemblyPath), Path.GetFileNameWithoutExtension(assemblyPath) + ".deps.json"))
				? new AssemblyLoader(assemblyPath).Assembly
				: AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);

		public Assembly Assembly { get; }
		ICompilationAssemblyResolver AssemblyResolver { get; }
		DependencyContext DependencyContext { get; }
		AssemblyLoadContext LoadContext { get; }

		public AssemblyLoader(string assemblyPath)
		{
			this.Assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
			this.DependencyContext = DependencyContext.Load(this.Assembly);

			this.AssemblyResolver = new CompositeCompilationAssemblyResolver(new ICompilationAssemblyResolver[]
			{
				new AppBaseCompilationAssemblyResolver(Path.GetDirectoryName(assemblyPath)),
				new ReferenceAssemblyPathResolver(),
				new PackageCompilationAssemblyResolver()
			});

			this.LoadContext = AssemblyLoadContext.GetLoadContext(this.Assembly);
			this.LoadContext.Resolving += (context, name) =>
			{
				var runtimeLibrary = this.DependencyContext.RuntimeLibraries.FirstOrDefault(runtime => string.Equals(runtime.Name, name.Name, StringComparison.OrdinalIgnoreCase));
				if (runtimeLibrary != null)
				{
					var compilationLibrary = new CompilationLibrary(
						runtimeLibrary.Type,
						runtimeLibrary.Name,
						runtimeLibrary.Version,
						runtimeLibrary.Hash,
						runtimeLibrary.RuntimeAssemblyGroups.SelectMany(g => g.AssetPaths),
						runtimeLibrary.Dependencies,
						runtimeLibrary.Serviceable
					);
					var assemblies = new List<string>();
					this.AssemblyResolver.TryResolveAssemblyPaths(compilationLibrary, assemblies);
					if (assemblies.Count > 0)
						return this.LoadContext.LoadFromAssemblyPath(assemblies[0]);
				}
				return null;
			};
		}
	}
}