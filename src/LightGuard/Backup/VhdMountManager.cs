// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// VHD 挂载信息。
/// </summary>
public sealed class VhdMountInfo
{
    /// <summary>VHD 文件路径。</summary>
    public string VhdPath { get; init; } = "";

    /// <summary>是否只读挂载。</summary>
    public bool ReadOnly { get; init; }

    /// <summary>挂载后的物理磁盘路径（如 \\?\PhysicalDrive2）。</summary>
    public string PhysicalPath { get; init; } = "";

    /// <summary>物理磁盘号（从 PhysicalPath 解析）。</summary>
    public int DiskNumber { get; init; } = -1;

    /// <summary>已分配的盘符（如 "E:"；无盘符卷为空）。</summary>
    public List<string> DriveLetters { get; } = new();

    /// <summary>卷 GUID 列表（\\?\Volume{...}\）。</summary>
    public List<string> VolumeGuids { get; } = new();
}

/// <summary>
/// VHD 虚拟磁盘挂载管理器（P0：裸机恢复 / 备份内容卷访问）。
/// <para>基于 Windows Virtual Disk API（virtdisk.dll）：Open → Attach → 卷盘符分配 / 回收 → Detach。</para>
/// <para>权限：Attach/Detach 需要管理员（或 SeBackupPrivilege），外部调用必须经
/// <see cref="PrivilegedWorker"/> 提权通道（Op = "VhdAttach" / "VhdDetach"）。</para>
/// <para>挂载识别：通过 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 将卷映射到物理磁盘号，
/// 与 GetVirtualDiskPhysicalPath 的磁盘号比对，精确识别本 VHD 的卷（不受其它磁盘干扰）。</para>
/// </summary>
public static class VhdMountManager
{
    // ==================== virtdisk 常量 ====================

    private const uint VIRTUAL_STORAGE_TYPE_DEVICE_VHD = 3;
    private static readonly Guid VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = new("EC984AEC-A0F9-47E9-901F-71415A66345B");

    private const uint OPEN_VIRTUAL_DISK_VERSION_1 = 1;
    private const uint ATTACH_VIRTUAL_DISK_VERSION_1 = 1;
    private const uint CREATE_VIRTUAL_DISK_VERSION_1 = 1;

    // VIRTUAL_DISK_ACCESS_MASK
    private const uint VIRTUAL_DISK_ACCESS_ATTACH_RO = 0x00010000;
    private const uint VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x00020000;
    private const uint VIRTUAL_DISK_ACCESS_DETACH = 0x00040000;
    private const uint VIRTUAL_DISK_ACCESS_CREATE = 0x00100000;

    // CREATE_VIRTUAL_DISK_FLAG
    private const uint CREATE_VIRTUAL_DISK_FLAG_NONE = 0x00000000;
    private const uint CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION = 0x00000001;

    // ATTACH_VIRTUAL_DISK_FLAG
    private const uint ATTACH_VIRTUAL_DISK_FLAG_NONE = 0x00000000;
    private const uint ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 0x00000001;

    // DETACH_VIRTUAL_DISK_FLAG
    private const uint DETACH_VIRTUAL_DISK_FLAG_NONE = 0x00000000;

    // 卷 → 磁盘映射 IOCTL
    private const uint IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // Win32 错误码
    private const uint ERROR_SUCCESS = 0;
    private const uint ERROR_FILE_NOT_FOUND = 2;
    private const uint ERROR_ACCESS_DENIED = 5;
    private const uint ERROR_NOT_READY = 21;
    private const uint ERROR_INVALID_DRIVE = 15;
    private const uint ERROR_VIRTDISK_INVALID_PARAMETER = 0xC03A0009;

    // ==================== Win32 结构体 ====================

    [StructLayout(LayoutKind.Sequential)]
    private struct VirtualStorageType
    {
        public uint DeviceId;
        public Guid VendorId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OpenVirtualDiskParameters
    {
        public uint Version;
        public uint GetInfoOnly; // Version1 union（仅 GetInfoOnly 标志位，0 = 正常打开）
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AttachVirtualDiskParameters
    {
        public uint Version;
        public uint Reserved; // Version1
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CreateVirtualDiskParameters
    {
        public uint Version;
        public Guid UniqueId;
        public long MaximumSize;
        public uint BlockSizeInBytes;
        public uint SectorSizeInBytes;
        public IntPtr ParentPath;   // null = 无父盘
        public IntPtr SourcePath;   // null = 空盘
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DiskExtent
    {
        public uint DiskNumber;
        public long StartingOffset;
        public long ExtentLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct VolumeDiskExtents
    {
        public uint NumberOfDiskExtents;
        public DiskExtent Extents; // 数组首元素；通常 VHD 单盘单区间
    }

    // ==================== P/Invoke ====================

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint OpenVirtualDisk(
        ref VirtualStorageType virtualStorageType,
        string path,
        uint virtualDiskAccessMask,
        uint flags,
        ref OpenVirtualDiskParameters parameters,
        out SafeDiskHandle handle);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint CreateVirtualDisk(
        ref VirtualStorageType virtualStorageType,
        string path,
        uint virtualDiskAccessMask,
        IntPtr securityDescriptor,
        uint flags,
        uint providerSpecificFlags,
        ref CreateVirtualDiskParameters parameters,
        IntPtr overlapped,
        out SafeDiskHandle handle);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint AttachVirtualDisk(
        SafeDiskHandle virtualDiskHandle,
        IntPtr securityDescriptor,
        uint flags,
        uint providerSpecificFlags,
        ref AttachVirtualDiskParameters parameters,
        IntPtr overlapped);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DetachVirtualDisk(
        SafeDiskHandle virtualDiskHandle,
        uint flags,
        uint providerSpecificFlags);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetVirtualDiskPhysicalPath(
        SafeDiskHandle virtualDiskHandle,
        ref uint diskPathSizeInBytes,
        [Out] char[] diskPathBuffer);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeVolumeHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeVolumeHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumePathNamesForVolumeNameW(
        string lpszVolumeName,
        [Out] char[] lpszVolumePathNames,
        uint cchBufferLength,
        out uint lpcchReturnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetVolumeMountPointW(
        string lpszVolumeMountPoint,
        string lpszVolumeName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool DeleteVolumeMountPointW(
        string lpszVolumeMountPoint);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstVolumeW(
        [Out] StringBuilder lpszVolumeName,
        uint cchBufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextVolumeW(
        IntPtr hFindVolume,
        [Out] StringBuilder lpszVolumeName,
        uint cchBufferLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindVolumeClose(IntPtr hFindVolume);

    /// <summary>磁盘句柄安全包装（CloseHandle 释放）。</summary>
    private sealed class SafeDiskHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeDiskHandle() : base(true) { }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    /// <summary>卷句柄安全包装（CloseHandle 释放）。</summary>
    private sealed class SafeVolumeHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeVolumeHandle() : base(true) { }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    // ==================== 公开 API ====================

    /// <summary>
    /// 创建新的 VHD 虚拟磁盘文件（裸机恢复目标盘 / 挂载测试用）。
    /// <para>需要管理员权限；外部调用应经 <see cref="PrivilegedWorker"/> 提权执行。</para>
    /// </summary>
    /// <param name="vhdPath">VHD 文件路径（.vhd / .vhdx 由扩展名决定）。</param>
    /// <param name="sizeMb">磁盘容量（MB，需 &gt; 0）。</param>
    /// <param name="fixedSize">true = 固定大小（FullPhysicalAllocation）；false = 动态增长。</param>
    /// <param name="overwrite">目标文件已存在时是否覆盖（先删除）。</param>
    public static void CreateVirtualDisk(string vhdPath, long sizeMb, bool fixedSize = true, bool overwrite = false)
    {
        if (string.IsNullOrWhiteSpace(vhdPath))
            throw new ArgumentException("VHD 路径不能为空。", nameof(vhdPath));
        if (sizeMb <= 0)
            throw new ArgumentOutOfRangeException(nameof(sizeMb), "磁盘容量必须大于 0。");

        var fullPath = Path.GetFullPath(vhdPath);
        if (File.Exists(fullPath))
        {
            if (!overwrite)
                throw new IOException($"VHD 文件已存在：{fullPath}（如需覆盖请传 overwrite: true）。");
            File.Delete(fullPath);
        }
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        ErrorReporter.Log($"VHD 创建开始：{fullPath} | {sizeMb} MB | {(fixedSize ? "固定" : "动态")}");

        var storageType = new VirtualStorageType
        {
            DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
        };
        var parameters = new CreateVirtualDiskParameters
        {
            Version = CREATE_VIRTUAL_DISK_VERSION_1,
            UniqueId = Guid.NewGuid(),
            MaximumSize = sizeMb * 1024L * 1024L,
            BlockSizeInBytes = 0,      // 0 = 默认
            SectorSizeInBytes = 512,
            ParentPath = IntPtr.Zero,
            SourcePath = IntPtr.Zero
        };
        uint flags = fixedSize ? CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION : CREATE_VIRTUAL_DISK_FLAG_NONE;

        var hErr = CreateVirtualDisk(ref storageType, fullPath,
            VIRTUAL_DISK_ACCESS_CREATE, IntPtr.Zero, flags, 0, ref parameters, IntPtr.Zero, out var handle);
        using (handle)
        {
            if (hErr != ERROR_SUCCESS)
                throw VhdError("创建 VHD 失败", hErr, fullPath);
        }

        ErrorReporter.Log($"VHD 创建完成：{fullPath} | {sizeMb} MB | {(fixedSize ? "固定" : "动态")}");
    }

    /// <summary>
    /// 挂载 VHD 虚拟磁盘，为其中每个卷分配盘符。
    /// <para>需要管理员权限；外部调用应经 <see cref="PrivilegedWorker"/> 提权执行。</para>
    /// </summary>
    /// <param name="vhdPath">VHD 文件路径（VHD / VHDX）。</param>
    /// <param name="readOnly">是否只读挂载（安全浏览，防写入宿主盘）。</param>
    /// <param name="assignDriveLetter">是否主动分配盘符（false 仅挂载不分配，供 Volume GUID 访问）。</param>
    /// <exception cref="FileNotFoundException">VHD 文件不存在。</exception>
    /// <exception cref="UnauthorizedAccessException">权限不足（非管理员）。</exception>
    /// <exception cref="IOException">挂载失败（Win32 错误）。</exception>
    public static VhdMountInfo Attach(string vhdPath, bool readOnly = true, bool assignDriveLetter = true)
    {
        if (string.IsNullOrWhiteSpace(vhdPath))
            throw new ArgumentException("VHD 路径不能为空。", nameof(vhdPath));
        if (!File.Exists(vhdPath))
            throw new FileNotFoundException("VHD 文件不存在。", vhdPath);

        var fullPath = Path.GetFullPath(vhdPath);
        ErrorReporter.Log($"VHD 挂载开始：{fullPath} | 只读={readOnly} | 分配盘符={assignDriveLetter}");

        var storageType = new VirtualStorageType
        {
            DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
        };
        var openParams = new OpenVirtualDiskParameters { Version = OPEN_VIRTUAL_DISK_VERSION_1, GetInfoOnly = 0 };
        uint accessMask = readOnly ? VIRTUAL_DISK_ACCESS_ATTACH_RO : VIRTUAL_DISK_ACCESS_ATTACH_RW | VIRTUAL_DISK_ACCESS_DETACH;

        var hErr = OpenVirtualDisk(ref storageType, fullPath, accessMask, 0, ref openParams, out var handle);
        using (handle)
        {
            if (hErr != ERROR_SUCCESS)
                throw VhdError("打开 VHD 失败", hErr, fullPath);

            var attachParams = new AttachVirtualDiskParameters { Version = ATTACH_VIRTUAL_DISK_VERSION_1, Reserved = 0 };
            uint flags = readOnly ? ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY : ATTACH_VIRTUAL_DISK_FLAG_NONE;
            hErr = AttachVirtualDisk(handle, IntPtr.Zero, flags, 0, ref attachParams, IntPtr.Zero);
            if (hErr != ERROR_SUCCESS)
                throw VhdError("挂载 VHD 失败", hErr, fullPath);
        }

        // 物理磁盘路径
        var (physicalPath, diskNumber) = QueryPhysicalPath(fullPath);

        // 识别本 VHD 的卷（物理磁盘号匹配）
        var volumes = EnumerateVolumesForDisk(diskNumber);
        var info = new VhdMountInfo { VhdPath = fullPath, ReadOnly = readOnly, PhysicalPath = physicalPath, DiskNumber = diskNumber };
        info.VolumeGuids.AddRange(volumes);

        // 分配盘符
        if (assignDriveLetter)
        {
            foreach (var volumeGuid in volumes)
            {
                var existing = GetVolumePathNames(volumeGuid);
                if (existing.Length > 0)
                {
                    info.DriveLetters.AddRange(existing);
                    continue;
                }
                var letter = FindFreeDriveLetter();
                if (letter == null)
                {
                    ErrorReporter.Log($"VHD 卷 {volumeGuid} 未找到空闲盘符，仅以卷 GUID 访问。", "WARN");
                    continue;
                }
                if (SetVolumeMountPointW(letter + ":\\", volumeGuid))
                {
                    info.DriveLetters.Add(letter + ":");
                    ErrorReporter.Log($"VHD 卷已分配盘符：{letter}: ← {volumeGuid}");
                }
                else
                {
                    var err = (uint)Marshal.GetLastWin32Error();
                    ErrorReporter.Log($"分配盘符 {letter}: 失败（Win32 {err}）。", "WARN");
                }
            }
        }

        ErrorReporter.Log($"VHD 挂载完成：{fullPath} → {physicalPath} | 卷 {info.VolumeGuids.Count} | 盘符 [{string.Join(", ", info.DriveLetters)}]");
        return info;
    }

    /// <summary>
    /// 卸载 VHD：回收本 VHD 卷的盘符并分离虚拟磁盘。
    /// </summary>
    /// <param name="vhdPath">VHD 文件路径（与挂载时一致）。</param>
    public static void Detach(string vhdPath)
    {
        if (string.IsNullOrWhiteSpace(vhdPath))
            throw new ArgumentException("VHD 路径不能为空。", nameof(vhdPath));
        if (!File.Exists(vhdPath))
        {
            ErrorReporter.Log($"VHD 文件不存在，跳过卸载：{vhdPath}", "WARN");
            return;
        }

        var fullPath = Path.GetFullPath(vhdPath);
        ErrorReporter.Log($"VHD 卸载开始：{fullPath}");

        var (_, diskNumber) = QueryPhysicalPath(fullPath);
        if (diskNumber >= 0)
        {
            // 回收本 VHD 卷的盘符
            foreach (var volumeGuid in EnumerateVolumesForDisk(diskNumber))
            {
                foreach (var path in GetVolumePathNames(volumeGuid))
                {
                    if (path.Length > 0 && path[^1] == '\\' && path.Length >= 3 && path[1] == ':')
                    {
                        var mountPoint = path;
                        if (DeleteVolumeMountPointW(mountPoint))
                            ErrorReporter.Log($"已回收盘符：{mountPoint} ← {volumeGuid}");
                    }
                }
            }
        }

        var storageType = new VirtualStorageType
        {
            DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
        };
        var openParams = new OpenVirtualDiskParameters { Version = OPEN_VIRTUAL_DISK_VERSION_1, GetInfoOnly = 0 };
        var hErr = OpenVirtualDisk(ref storageType, fullPath,
            VIRTUAL_DISK_ACCESS_DETACH, 0, ref openParams, out var handle);
        using (handle)
        {
            if (hErr != ERROR_SUCCESS)
            {
                // 未挂载时 Detach 通常返回 0xC03A0009 或文件未找到；视为已分离，不阻断
                ErrorReporter.Log($"打开 VHD 用于卸载失败（Win32 0x{hErr:X8}）：{fullPath}", "WARN");
                return;
            }
            hErr = DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
            if (hErr != ERROR_SUCCESS)
                throw VhdError("卸载 VHD 失败", hErr, fullPath);
        }

        ErrorReporter.Log($"VHD 卸载完成：{fullPath}");
    }

    /// <summary>列出当前已挂载（Attach）的 VHD 物理磁盘路径（System Drive 之外的物理盘）。</summary>
    public static List<string> ListAttachedPhysicalDisks()
    {
        var result = new List<string>();
        for (uint n = 0; n < 32; n++)
        {
            var diskPath = $@"\\.\PhysicalDrive{n}";
            try
            {
                using var h = CreateFileW(diskPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (!h.IsInvalid)
                    result.Add($@"\\.\PhysicalDrive{n}");
            }
            catch { break; }
        }
        return result;
    }

    // ==================== 内部实现 ====================

    /// <summary>查询 VHD 的物理磁盘路径与磁盘号。</summary>
    private static (string PhysicalPath, int DiskNumber) QueryPhysicalPath(string vhdPath)
    {
        var storageType = new VirtualStorageType
        {
            DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
        };
        var openParams = new OpenVirtualDiskParameters { Version = OPEN_VIRTUAL_DISK_VERSION_1, GetInfoOnly = 0 };
        var hErr = OpenVirtualDisk(ref storageType, vhdPath,
            VIRTUAL_DISK_ACCESS_ATTACH_RO, 0, ref openParams, out var handle);
        using (handle)
        {
            if (hErr != ERROR_SUCCESS)
                return ("", -1);

            uint size = 0;
            GetVirtualDiskPhysicalPath(handle, ref size, Array.Empty<char>());
            var buf = new char[size];
            hErr = GetVirtualDiskPhysicalPath(handle, ref size, buf);
            if (hErr != ERROR_SUCCESS || size == 0)
                return ("", -1);

            var path = new string(buf, 0, (int)size - 1); // 去掉结尾 NUL
            int diskNumber = -1;
            var prefix = "PhysicalDrive";
            var idx = path.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0 && int.TryParse(path.AsSpan(idx + prefix.Length), out var dn))
                diskNumber = dn;
            return (path, diskNumber);
        }
    }

    /// <summary>枚举指定物理磁盘号上的全部卷 GUID（IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 比对）。</summary>
    private static List<string> EnumerateVolumesForDisk(int diskNumber)
    {
        var result = new List<string>();
        if (diskNumber < 0) return result;

        var buf = new StringBuilder(512);
        var find = FindFirstVolumeW(buf, 512);
        if (find == new IntPtr(-1))
            return result;
        try
        {
            do
            {
                var volumeGuid = buf.ToString().TrimEnd('\\') + "\\";
                if (VolumeBelongsToDisk(volumeGuid, diskNumber))
                    result.Add(volumeGuid);
                buf.Clear();
            }
            while (FindNextVolumeW(find, buf, 512));
        }
        finally
        {
            FindVolumeClose(find);
        }
        return result;
    }

    /// <summary>通过 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 判断卷是否位于指定物理磁盘上。</summary>
    private static bool VolumeBelongsToDisk(string volumeGuid, int diskNumber)
    {
        using var h = CreateFileW(volumeGuid, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return false;

        var extentsSize = Marshal.SizeOf<VolumeDiskExtents>();
        var outBuf = Marshal.AllocHGlobal(extentsSize);
        try
        {
            if (!DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    IntPtr.Zero, 0, outBuf, (uint)extentsSize, out _, IntPtr.Zero))
                return false;
            var ex = Marshal.PtrToStructure<VolumeDiskExtents>(outBuf);
            return ex.NumberOfDiskExtents == 1 && (int)ex.Extents.DiskNumber == diskNumber;
        }
        finally
        {
            Marshal.FreeHGlobal(outBuf);
        }
    }

    /// <summary>获取卷 GUID 的挂载路径（盘符，多路径以 '\0' 分隔）。</summary>
    private static string[] GetVolumePathNames(string volumeGuid)
    {
        uint size = 0;
        GetVolumePathNamesForVolumeNameW(volumeGuid, Array.Empty<char>(), 0, out size);
        if (size == 0) return Array.Empty<string>();
        var buf = new char[size];
        if (!GetVolumePathNamesForVolumeNameW(volumeGuid, buf, size, out _))
            return Array.Empty<string>();
        var joined = new string(buf);
        return joined.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>查找空闲盘符（C 之后，跳过当前占用；不分配 A/B 软驱）。</summary>
    private static string? FindFreeDriveLetter()
    {
        for (char c = 'D'; c <= 'Z'; c++)
        {
            var letter = c.ToString();
            if (Directory.Exists($"{letter}:\\"))
                continue;
            return letter;
        }
        return null;
    }

    /// <summary>将 Win32 错误码转换为带中文说明的异常。</summary>
    private static IOException VhdError(string action, uint hErr, string vhdPath)
    {
        var message = hErr switch
        {
            ERROR_FILE_NOT_FOUND => "VHD 文件不存在或不可访问。",
            ERROR_ACCESS_DENIED => "权限不足（VHD 挂载需要管理员权限）。",
            ERROR_INVALID_DRIVE => "无效盘符。",
            ERROR_VIRTDISK_INVALID_PARAMETER => "VHD 参数无效（文件可能已损坏或正被占用）。",
            _ => new Win32Exception((int)hErr).Message
        };
        return new IOException($"{action}：{vhdPath}（Win32 0x{hErr:X8}：{message}）");
    }
}
