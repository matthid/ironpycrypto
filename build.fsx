// --------------------------------------------------------------------------------------
// FAKE build script
// --------------------------------------------------------------------------------------

#I @"packages/build/FAKE/tools"
#r @"packages/build/FAKE/tools/FakeLib.dll"
#r @"packages/build/sharpcompress/lib/net40/SharpCompress.dll"


open System
open System.IO
open System.Net
open Fake
open SharpCompress
open SharpCompress.Reader
open SharpCompress.Archive
open SharpCompress.Common

Environment.CurrentDirectory <- __SOURCE_DIRECTORY__ 

/// Run the given buildscript with FAKE.exe
let executeWithOutput configStartInfo =
    let exitCode =
        ExecProcessWithLambdas
            configStartInfo
            TimeSpan.MaxValue false ignore ignore
    System.Threading.Thread.Sleep 1000
    exitCode

let extract dir file =
  use stream = File.OpenRead(file)
  let reader = ReaderFactory.Open(stream)
  reader.WriteAllToDirectory (dir, ExtractOptions.ExtractFullPath)

// Documentation
let execute traceMsg failMessage configStartInfo =
    trace traceMsg
    let exit = executeWithOutput configStartInfo
    if exit <> 0 then
        failwith failMessage
    ()

let downloadFile target url =
  async {
    use c = new WebClient()
    do! c.AsyncDownloadFile(new Uri(url), target)
  }

let ipyW workingDir args =
  execute
    (sprintf "Starting IronPython with '%s'" args)
    "Failed to process ironpython command"
    (fun info ->
      info.FileName <- System.IO.Path.GetFullPath "temp/IronPython/ipy.exe"
      info.Arguments <- args
      info.WorkingDirectory <- workingDir
      let setVar k v =
          info.EnvironmentVariables.[k] <- v
      setVar "PYTHONPATH" (Path.GetFullPath "temp/IronPython"))
let ipy args = ipyW "temp/IronPython" args

Target "SetupIronPython" (fun _ ->
    CleanDir "temp/IronPython"
    CopyDir ("temp"@@"IronPython") ("packages"@@"IronPython"@@"lib"@@"Net45") (fun _ -> true)
    CopyDir ("temp"@@"IronPython") ("packages"@@"IronPython"@@"tools") (fun _ -> true)

    CopyDir ("temp"@@"IronPython") ("packages"@@"IronPython.StdLib"@@"content") (fun _ -> true)
    ipy "-X:Frames -m ensurepip"
)

Target "Build" (fun _ ->
    !! "IronPyCrypto.sln"
    |> MSBuildRelease "" "Rebuild"
    |> ignore
)

Target "SetupIronPythonForTests" (fun _ ->
    CopyDir 
      ("temp"@@"IronPython"@@"Lib"@@"site-packages"@@"Crypto")
      ("Crypto") (fun _ -> true)

    ensureDirectory ("temp"@@"IronPython"@@"DLLs")
    CopyFile ("temp"@@"IronPython"@@"DLLs") ("IronPyCrypto"@@"bin"@@"Release"@@"IronPyCrypto.dll")
    //File.Delete("Testing"@@"bin"@@"Release"@@"IronPyCrypto.dll")
)

Target "RunTests" (fun _ ->
  execute
    (sprintf "Starting Tests with...")
    "Failed to start tests."
    (fun info ->
      info.FileName <- System.IO.Path.GetFullPath "Testing/bin/Release/Testing.exe"
      info.Arguments <- ""
      info.WorkingDirectory <- System.IO.Path.GetFullPath "Testing/bin/Release"
      let setVar k v =
          info.EnvironmentVariables.[k] <- v
      setVar "PYTHONPATH" (Path.GetFullPath "temp/IronPython"))
)

Target "All" DoNothing

"SetupIronPython" 
  ==> "Build"
  ==> "SetupIronPythonForTests"
  ==> "RunTests"
  ==> "All"


RunTargetOrDefault "All"
