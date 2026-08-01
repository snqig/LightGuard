namespace LightGuard.Core;

/// <summary>
/// 消息框辅助类 - 通俗中文提示
/// </summary>
internal static class MessageBoxHelper
{
    public static void Info(string message, string title = "LightGuard 提示")
        => System.Windows.Forms.MessageBox.Show(message, title,
            System.Windows.Forms.MessageBoxButtons.OK,
            System.Windows.Forms.MessageBoxIcon.Information);

    public static void Warn(string message, string title = "LightGuard 警告")
        => System.Windows.Forms.MessageBox.Show(message, title,
            System.Windows.Forms.MessageBoxButtons.OK,
            System.Windows.Forms.MessageBoxIcon.Warning);

    public static void Error(string message, string title = "LightGuard 错误")
        => System.Windows.Forms.MessageBox.Show(message, title,
            System.Windows.Forms.MessageBoxButtons.OK,
            System.Windows.Forms.MessageBoxIcon.Error);

    public static bool Confirm(string message, string title = "LightGuard 确认")
        => System.Windows.Forms.MessageBox.Show(message, title,
            System.Windows.Forms.MessageBoxButtons.YesNo,
            System.Windows.Forms.MessageBoxIcon.Question)
            == System.Windows.Forms.DialogResult.Yes;
}
