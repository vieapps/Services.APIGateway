#region Related components
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyModel;
using Microsoft.Extensions.DependencyModel.Resolution;
#endregion

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
			=> !File.Exists(Path.Combine(Path.GetDirectoryName(assemblyPath), Path.GetFileNameWithoutExtension(assemblyPath) + ".deps.json"))
				? AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath)
				: new AssemblyLoader(assemblyPath).Assembly;

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
				var runtimeLib = this.DependencyContext.RuntimeLibraries.FirstOrDefault(runtime => string.Equals(runtime.Name, name.Name, StringComparison.OrdinalIgnoreCase));
				if (runtimeLib != null)
				{
					var compilationLib = new CompilationLibrary(
						runtimeLib.Type,
						runtimeLib.Name,
						runtimeLib.Version,
						runtimeLib.Hash,
						runtimeLib.RuntimeAssemblyGroups.SelectMany(g => g.AssetPaths),
						runtimeLib.Dependencies,
						runtimeLib.Serviceable
					);
					var assemblyPaths = new List<string>();
					this.AssemblyResolver.TryResolveAssemblyPaths(compilationLib, assemblyPaths);
					if (assemblyPaths.Count > 0)
						return this.LoadContext.LoadFromAssemblyPath(assemblyPaths[0]);
				}
				return null;
			};
		}
	}
}