using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;

static class Program
{
    static void Main(string[] args)
    {
        var path = Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>().Single(attribute => attribute.Key == "OriginalDiskInfoAssembly").Value!;
        var original = Load(path, "original");
        var candidate = typeof(DiskInfoToolkit.Storage).Assembly.GetType("DiskInfoToolkit.PCI.PCIIDReader", throwOnError: true)!;
        var vendors = ((IEnumerable)original.GetProperty("Vendors", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!).Cast<object>().ToArray();
        var cases = new HashSet<(ushort, ushort)> { (0, 0), (0xffff, 0xffff), (0x8086, 0xffff), (0x10de, 0xffff), (0x144d, 0xa809) };
        foreach (var vendor in vendors.Where((_, i) => i % 31 == 0 || i == vendors.Length - 1))
        {
            int id = (int)vendor.GetType().GetProperty("ID")!.GetValue(vendor)!;
            if (id < 0 || id > ushort.MaxValue) continue;
            var devices = ((IEnumerable)vendor.GetType().GetProperty("Devices")!.GetValue(vendor)!).Cast<object>().ToArray();
            cases.Add(((ushort)id, 0xffff));
            foreach (var device in devices.Take(1).Concat(devices.TakeLast(1)))
            {
                int deviceId = (int)device.GetType().GetProperty("ID")!.GetValue(device)!;
                if (deviceId >= 0 && deviceId <= ushort.MaxValue) cases.Add(((ushort)id, (ushort)deviceId));
            }
        }
        foreach (var pair in cases)
        {
            var expected = Find(original, pair);
            var actual = Find(candidate, pair);
            if (expected != actual) throw new Exception($"Mismatch {pair.Item1:x4}:{pair.Item2:x4}: {expected} != {actual}");
        }
        Console.WriteLine($"PCI lookup equivalence passed: {cases.Count} cases across {vendors.Length} original vendors");
        var candidateVendors = (ICollection)candidate.GetProperty("Vendors", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!;
        if (candidateVendors.Count != 0) throw new Exception("Candidate retained PCI catalog");
    }
    static Type Load(string path, string name)
    {
        var context = new AssemblyLoadContext(name, isCollectible: true);
        return context.LoadFromAssemblyPath(Path.GetFullPath(path)).GetType("DiskInfoToolkit.PCI.PCIIDReader", throwOnError: true)!;
    }
    static (bool, string, string) Find(Type type, (ushort, ushort) ids)
    {
        object?[] values = { ids.Item1, ids.Item2, null, null };
        bool found = (bool)type.GetMethod("TryGetVendorAndDeviceName", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, values)!;
        return (found, (string)values[2]!, (string)values[3]!);
    }
}

