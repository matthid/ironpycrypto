/*
 * Created by SharpDevelop.
 * User: David Lawler
 * Date: 1/12/2010
 * Time: 4:20 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections.Generic;
using System.IO;
using IronPyCrypto.Cipher;
using IronPyCrypto.Util;
using IronPython.Hosting;
using Microsoft.Scripting.Hosting;

namespace Testing
{
    class Program
    {
        public static void Main(string[] args)
        {

            if (true)      // use this to test something specific
            {
                byte[] keyb = new byte[1] { 0x01 };
                byte[] datab = new byte[8] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
                string key = StringBytes.BytesToString(keyb);
                string data = StringBytes.BytesToString(datab);
                XOR xor = XOR.@new(key);
                string res = xor.encrypt(data);
                Console.WriteLine(StringBytes.StringToHexString(res));
            }

            if (true)       // run entire (standard) PyCrypto test suite
            {
                Dictionary<string, object> options = new Dictionary<string, object>();
                // options["Debug"] = true;
                ScriptEngine pyEngine = Python.CreateEngine(options);
                //pyEngine.Runtime.LoadAssembly(typeof(Strxor).Assembly);
                ScriptScope pyScope = pyEngine.CreateScope();
                // assumes we are running in Testing\bin\Debug...so we have to go up three dirs to find the script
                // string scriptPath = Path.GetFullPath(Path.Combine("..\\..\\..\\", "demo.py"));
                var current = Environment.CurrentDirectory;
                
                var solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(current)));
                string scriptPath = Path.Combine(solutionDir, "runtests.py");
                string[] searchPaths = new String[5];

                var pythonPath = Path.Combine(solutionDir, "temp", "IronPython");
                Console.WriteLine("Using python path '{0}'", pythonPath);
                searchPaths[1] = pythonPath;
                //searchPaths[2] = Path.Combine(pythonPath, "DLLs");
                searchPaths[2] = current;
                searchPaths[3] = Path.Combine(pythonPath, "Lib");
                searchPaths[4] = Path.Combine(pythonPath, "Lib", "site-packages");
                searchPaths[0] = Path.GetDirectoryName(scriptPath);
                pyEngine.SetSearchPaths(searchPaths);
                
                ScriptSource source = pyEngine.CreateScriptSourceFromFile(scriptPath);
                CompiledCode compiled = source.Compile();
                compiled.Execute(pyScope);
            }
        }
    }
}