// ============================================================
//  UDPLIB.cs - managed-мост Unity (Assembly-CSharp) к нативной
//  библиотеке udplib.dll / libudplib.so.
//
//  Размещение плагинов (заполняет build.sh):
//    Assets/UDPLIB/Plugins/x86_64/udplib.dll      (Windows 64)
//    Assets/UDPLIB/Plugins/Linux/x86_64/libudplib.so (Linux 64)
//
//  Мост:
//    * при старте игры выводит в консоль версию и билд ("udplib");
//    * поднимает нативный UDP/TCP-сервер;
//    * опрашивает консольные команды игры и пробрасывает их в сервер;
//    * перехватывает вывод консоли и рассылает UDP-клиентам как EVENT.
// ============================================================
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using UnityEngine;

namespace UDPLIB
{
    [StructLayout(LayoutKind.Sequential)]
    public struct UdplibVersionInfo
    {
        public int major;
        public int minor;
        public int patch;
        public int build;
    }

    public static class Native
    {
#if UNITY_EDITOR_WIN || UNITY_STANDALONE_WIN
        const string LIB = "udplib";           // udplib.dll
#else
        const string LIB = "udplib";           // libudplib.so (Mono добавляет lib/.so)
#endif

        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern int udplib_init(uint udp_port, uint tcp_port);
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void udplib_shutdown();
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern int udplib_is_active();
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr udplib_version_string();
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr udplib_build_string();
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void udplib_get_console_text(IntPtr outBuf, int outLen);
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern int udplib_check_password(string passwordUtf8);
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void udplib_broadcast_event(string textUtf8);
        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern int udplib_udp_client_count();

        static string PtrToAnsi(IntPtr p)
            => p == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(p) ?? "";

        public static string VersionString() => PtrToAnsi(udplib_version_string());
        public static string BuildString()   => PtrToAnsi(udplib_build_string());
    }

    /// <summary>Точка входа: создаётся автоматически на старте сцены.</summary>
    public class UdplibBoot : MonoBehaviour
    {
        static UdplibBoot _instance;
        ConsoleHook _hook;

        public static void EnsureExists()
        {
            if (_instance != null) return;
            var go = new GameObject("[UDPLIB]");
            DontDestroyOnLoad(go);
            _instance = go.AddComponent<UdplibBoot>();
        }

        void Awake()
        {
            if (_instance != null && _instance != this) { Destroy(gameObject); return; }
            _instance = this;

            int rc = Native.udplib_init(0, 0);   // 0 -> порты по умолчанию из udplib_common.h
            Debug.Log(rc != 0
                ? Native.VersionString() + ", " + Native.BuildString()
                : "[UDPLIB] failed to start server (port busy?)");

            _hook = new ConsoleHook();
            _hook.Attach();
        }

        void OnDestroy()
        {
            _hook?.Detach();
            Native.udplib_shutdown();
            if (_instance == this) _instance = null;
        }

        void Update()
        {
            // события из игры -> всем чистым UDP-клиентам
            string line = _hook?.DequeueConsoleLine();
            if (!string.IsNullOrEmpty(line))
                Native.udplib_broadcast_event(line);
        }
    }

    /// <summary>
    /// Хук консоли игры: подписывается на Application.logMessageReceived
    /// и (если доступен) на статический OnCommandLineSubmit делегат мода.
    /// Команда "udplib" печатает версию/билд/число клиентов.
    /// </summary>
    public class ConsoleHook
    {
        readonly System.Collections.Generic.Queue<string> _queue = new();
        bool _attached;

        public void Attach()
        {
            if (_attached) return;
            Application.logMessageReceived += OnLog;
            TryAttachGameDelegate();
            _attached = true;
        }

        public void Detach()
        {
            if (!_attached) return;
            Application.logMessageReceived -= OnLog;
            _attached = false;
        }

        void OnLog(string condition, string stack, LogType type)
        {
            lock (_queue) _queue.Enqueue(condition);
        }

        public string DequeueConsoleLine()
        {
            lock (_queue) return _queue.Count > 0 ? _queue.Dequeue() : null;
        }

        void TryAttachGameDelegate()
        {
            // Пытаемся найти модовый делегат ввода консоли рефлексом, чтобы
            // не линковаться жёстко на этапе компиляции модуля.
            try
            {
                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    var t = asm.GetType("ModKit.ConsoleInput");
                    if (t == null) continue;
                    var evt = t.GetEvent("OnCommandLineSubmit", BindingFlags.Public | BindingFlags.Static);
                    var m = GetType().GetMethod(nameof(OnGameCommand),
                                                BindingFlags.Instance | BindingFlags.NonPublic);
                    if (evt != null && m != null)
                        evt.AddEventHandler(null, Delegate.CreateDelegate(evt.EventHandlerType, this, m));
                    return;
                }
            }
            catch (Exception e)
            {
                Debug.LogWarning("[UDPLIB] console hook unavailable: " + e.Message);
            }
        }

        void OnGameCommand(string cmd)
        {
            if (cmd == null) return;
            cmd = cmd.Trim();
            if (cmd.Equals("udplib", StringComparison.OrdinalIgnoreCase))
            {
                Debug.Log(Native.VersionString() + "\n" + Native.BuildString() +
                          "\nudp clients: " + Native.udplib_udp_client_count());
            }
        }
    }

    /// <summary>Регистрация точки входа для игрового модпака (SPT-style).</summary>
    public static class ModEntry
    {
        // Сигнатура совпадает с ожидаемой загрузчиком модов:
        //   public static void Entry(ModLoaderBase loader)
        // Тип параметра неизвестен на этапе компиляции standalone-модуля,
        // поэтому принимаем object и подключаемся рефлексивно.
        public static void Entry(object modLoader)
        {
            try
            {
                var t = modLoader?.GetType();
                var registerMethod = t?.GetMethod("RegisterAsAChild",
                    BindingFlags.Public | BindingFlags.Instance);
                registerMethod?.Invoke(modLoader, new object[] { "UDPLIB" });
            }
            catch (Exception e)
            {
                Debug.LogWarning("[UDPLIB] modloader register skipped: " + e.Message);
            }
            UdplibBoot.EnsureExists();
        }
    }
}
