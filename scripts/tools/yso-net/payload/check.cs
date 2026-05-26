using System;
using System.IO;
using System.Web;
using System.Collections.Generic;

class E
{
    public E()
    {
        HttpContext context = HttpContext.Current;
        context.Server.ClearError();
        context.Response.Clear();
        try
        {
            // 获取应用程序基目录
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            
            // 获取所有有权限写入的目录
            List<string> writableDirectories = GetWritableDirectories(baseDirectory);
            
            // 输出结果
            context.Response.Write("Writable directories:<br>");
            foreach (string dir in writableDirectories)
            {
                context.Response.Write(dir + "<br>");
            }
        }
        catch (Exception ex)
        {
            context.Response.Write("Error: " + ex.Message);
        }
        finally
        {
            context.Response.Flush();
            context.Response.End();
        }
    }

    private List<string> GetWritableDirectories(string baseDirectory)
    {
        List<string> writableDirectories = new List<string>();
        try
        {
            // 检查基目录本身是否有写入权限
            if (IsDirectoryWritable(baseDirectory))
            {
                writableDirectories.Add(baseDirectory);
            }

            // 遍历基目录下的所有子目录
            Stack<string> directoriesToCheck = new Stack<string>();
            directoriesToCheck.Push(baseDirectory);

            while (directoriesToCheck.Count > 0)
            {
                string currentDir = directoriesToCheck.Pop();
                try
                {
                    foreach (string subDir in Directory.GetDirectories(currentDir))
                    {
                        if (IsDirectoryWritable(subDir))
                        {
                            writableDirectories.Add(subDir);
                        }
                        directoriesToCheck.Push(subDir);
                    }
                }
                catch (Exception ex)
                {
                    // 忽略无法访问的目录
                }
            }
        }
        catch (Exception ex)
        {
            // 忽略无法访问的目录
        }

        return writableDirectories;
    }

    private bool IsDirectoryWritable(string directory)
    {
        try
        {
            // 尝试创建一个临时文件并立即删除
            string tempFile = Path.Combine(directory, "temp_" + Guid.NewGuid().ToString() + ".tmp");
            File.WriteAllText(tempFile, string.Empty);
            File.Delete(tempFile);
            return true;
        }
        catch
        {
            return false;
        }
    }
}