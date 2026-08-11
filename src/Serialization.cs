using System.Text.Json.Serialization;
namespace Gcexp.Serialization;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true, UseStringEnumConverter = true)]
[JsonSerializable(typeof(ScanReport))]
internal sealed partial class GcexpJsonContext : JsonSerializerContext;
