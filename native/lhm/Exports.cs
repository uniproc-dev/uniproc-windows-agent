using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using LibreHardwareMonitor.Hardware;

namespace Uniproc.Lhm;

public static unsafe class Exports
{
    private static readonly object Gate = new();
    private static Computer? Computer;
    private static long LastCollection = Environment.TickCount64;
    private static byte[] Snapshot = Failure("unavailable", "Backend has not been opened");

    [UnmanagedCallersOnly(EntryPoint = "lhm_abi_version")]
    public static uint Version() => 1;

    [UnmanagedCallersOnly(EntryPoint = "lhm_open")]
    public static int Open()
    {
        lock (Gate)
        {
            if (Computer is not null) return 0;
            try
            {
                var computer = new Computer
                {
                    IsCpuEnabled = true,
                    IsGpuEnabled = true,
                    IsMemoryEnabled = true,
                    IsStorageEnabled = true
                };
                Computer = computer;
                computer.Open();
                LastCollection = Environment.TickCount64;
                return 0;
            }
            catch (Exception error)
            {
                Snapshot = Failure("error", error.Message);
                try { Computer?.Close(); } catch { }
                Computer = null;
                return -1;
            }
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "lhm_update")]
    public static int Update()
    {
        lock (Gate)
        {
            if (Computer is null) return -1;
            try
            {
                var buffer = new ArrayBufferWriter<byte>();
                using (var json = new Utf8JsonWriter(buffer))
                {
                    json.WriteStartObject();
                    json.WriteString("status", "available");
                    json.WriteString("error", "");
                    json.WriteStartArray("devices");
                    var packages = new List<double?>();
                    foreach (IHardware hardware in Computer.Hardware) Collect(json, hardware, "unknown", packages);
                    json.WriteEndArray();
                    if (CpuPackagePower.Total(packages) is double watts) json.WriteNumber("cpu_package_power_watts", watts);
                    else json.WriteNull("cpu_package_power_watts");
                    json.WriteEndObject();
                }
                Snapshot = buffer.WrittenSpan.ToArray();
                if (Environment.TickCount64 - LastCollection >= 60_000)
                {
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
                    LastCollection = Environment.TickCount64;
                }
                return 0;
            }
            catch (Exception error)
            {
                Snapshot = Failure("error", error.Message);
                return -1;
            }
        }
    }

    private static void Collect(Utf8JsonWriter json, IHardware hardware, string parentCategory, List<double?> packages)
    {
        string category = hardware.HardwareType switch
        {
            HardwareType.Cpu => "cpu",
            HardwareType.GpuNvidia or HardwareType.GpuAmd or HardwareType.GpuIntel => "gpu",
            HardwareType.Memory => "memory",
            HardwareType.Storage => "storage",
            _ => parentCategory
        };
        string error = "";
        try
        {
            foreach (ISensor sensor in hardware.Sensors) sensor.ValuesTimeWindow = TimeSpan.Zero;
            hardware.Update();
        }
        catch (Exception failure) { error = failure.Message; }
        if (hardware.HardwareType == HardwareType.Cpu)
            packages.Add(CpuPackagePower.Read(hardware.Sensors.Select(sensor =>
                (sensor.SensorType == SensorType.Power, sensor.Name, sensor.Value)), error.Length != 0));
        int temperatures = 0;
        foreach (ISensor sensor in hardware.Sensors)
        {
            sensor.ValuesTimeWindow = TimeSpan.Zero;
            if (IsReading(sensor, category)) temperatures++;
        }
        json.WriteStartObject();
        json.WriteString("id", hardware.Identifier.ToString());
        json.WriteString("name", hardware.Name);
        json.WriteString("category", category);
        json.WriteString("status", error.Length != 0 ? "error" : temperatures == 0 ? "unavailable" : "available");
        json.WriteString("error", error);
        json.WriteStartArray("sensors");
        foreach (ISensor sensor in hardware.Sensors)
        {
            if (!IsReading(sensor, category)) continue;
            json.WriteStartObject();
            json.WriteString("id", sensor.Identifier.ToString());
            json.WriteString("name", sensor.Name);
            float? value = error.Length == 0 ? sensor.Value : null;
            if (value.HasValue && float.IsFinite(value.Value)) json.WriteNumber("celsius", value.Value);
            else json.WriteNull("celsius");
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
        foreach (IHardware child in hardware.SubHardware) Collect(json, child, category, packages);
    }

    [UnmanagedCallersOnly(EntryPoint = "lhm_read")]
    public static int Read(byte* output, int capacity)
    {
        lock (Gate)
        {
            if (capacity < 0) return -1;
            if (output is not null && capacity >= Snapshot.Length)
                Snapshot.AsSpan().CopyTo(new Span<byte>(output, capacity));
            return Snapshot.Length;
        }
    }

    private static bool IsReading(ISensor sensor, string category) =>
        sensor.SensorType == SensorType.Temperature &&
        !sensor.Name.EndsWith(" Distance to TjMax", StringComparison.Ordinal) &&
        (category != "storage" || sensor.Name is not ("Warning Temperature" or "Critical Temperature")) &&
        (category != "memory" || sensor.GetType().FullName == "LibreHardwareMonitor.Hardware.Memory.Sensors.SpdThermalSensor");

    [UnmanagedCallersOnly(EntryPoint = "lhm_close")]
    public static void Close()
    {
        lock (Gate)
        {
            try { Computer?.Close(); } catch { }
            Computer = null;
            Snapshot = Failure("unavailable", "Backend is closed");
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
        }
    }

    private static byte[] Failure(string status, string error)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("status", status);
            json.WriteString("error", error);
            json.WriteNull("cpu_package_power_watts");
            json.WriteStartArray("devices");
            json.WriteEndArray();
            json.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }
}
