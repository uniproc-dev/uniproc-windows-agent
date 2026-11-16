using System;
using System.Collections.Generic;

namespace Uniproc.Lhm;

public static class CpuPackagePower
{
    public static double? Read(IEnumerable<(bool IsPower, string Name, float? Value)> sensors, bool failed)
    {
        if (failed) return null;
        int count = 0;
        double? watts = null;
        foreach (var sensor in sensors)
        {
            if (!sensor.IsPower || sensor.Name is not ("CPU Package" or "Package")) continue;
            count++;
            if (sensor.Value is float value && float.IsFinite(value) && value >= 0) watts = value;
        }
        return count == 1 ? watts : null;
    }

    public static double? Total(IReadOnlyList<double?> packages)
    {
        if (packages.Count == 0) return null;
        double sum = 0;
        foreach (double? package in packages)
        {
            if (package is not double watts || !double.IsFinite(watts) || watts < 0) return null;
            sum += watts;
        }
        return double.IsFinite(sum) ? sum : null;
    }
}
