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

    let installPackageE ext name version md5 =
      let targetFile = sprintf "temp/IronPython/%s-%s%s" name version ext
      downloadFile
        targetFile
        (sprintf "https://pypi.python.org/packages/source/p/%s/%s-%s%s#md5=%s" name name version ext md5)
        |> Async.RunSynchronously
      let distDir = "temp/IronPython/dist" // sprintf "temp/IronPython/%s-%s" name version
      let targetDir = sprintf "%s/%s-%s" distDir name version
      CleanDir targetDir
      extract targetDir targetFile
      let containsSetup dir = File.Exists (sprintf "%s/setup.py" dir)
      if containsSetup targetDir then
        ipyW targetDir "-X:Frames setup.py install"
      else
        let subDir = sprintf "%s/%s-%s" targetDir name version
        if containsSetup subDir then
          ipyW subDir "-X:Frames setup.py install"
        else
          failwith "Could not find setup.py in package!"
    let installPackage = installPackageE ".tar.gz"

    // Install patch, such that we can apply our patches :)
    installPackageE ".zip" "patch" "1.16" "dbcbbd4e45ddd8baeb02bddf663a3176"
    
    let patch patchFile =
      ipy (sprintf "-X:Frames -m patch -v ../../patches/%s" patchFile)

    patch "patch_pip.patch"
    
    // install protobuf manually
    downloadFile
      "temp/IronPython/protobuf-3.0.0a3-py2-none-any.whl"
      "https://github.com/GoogleCloudPlatform/gcloud-python-wheels/raw/master/wheelhouse/protobuf-3.0.0a3-py2-none-any.whl"
      |> Async.RunSynchronously
    ipy "-X:Frames -m pip install protobuf-3.0.0a3-py2-none-any.whl"


    // install pyasn1 manually
    installPackage "pyasn1" "0.1.8" "7f6526f968986a789b1e5e372f0b7065"
    //downloadFile
    //  "temp/IronPython/pyasn1-0.1.8.tar.gz"
    //  "https://pypi.python.org/packages/source/p/pyasn1/pyasn1-0.1.8.tar.gz#md5=7f6526f968986a789b1e5e372f0b7065"
    //  |> Async.RunSynchronously
    //CleanDir "temp/IronPython/pyasn1-0.1.8"
    //extract "temp/IronPython/pyasn1-0.1.8" "temp/IronPython/pyasn1-0.1.8.tar.gz"
    //ipy "-X:Frames pyasn1-0.1.8/setup.py install"

    // install pyasn1-modules manually
    installPackage "pyasn1-modules" "0.0.6" "3b94e7a4999bc7477b76c46c30a56727"
    //downloadFile
    //  "temp/IronPython/pyasn1-modules-0.0.6.tar.gz"
    //  "https://pypi.python.org/packages/source/p/pyasn1-modules/pyasn1-modules-0.0.6.tar.gz#md5=3b94e7a4999bc7477b76c46c30a56727"
    //  |> Async.RunSynchronously
    //CleanDir "temp/IronPython/pyasn1-modules-0.0.6"
    //extract "temp/IronPython/pyasn1-modules-0.0.6" "temp/IronPython/pyasn1-modules-0.0.6.tar.gz"
    //ipy "-X:Frames pyasn1-modules-0.0.6/setup.py install"

    // Install pycrypto
    ipy "-X:Frames -m easy_install http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe"

    ipy "-X:Frames -m pip install http"
    ipy "-X:Frames -m pip install gmusicapi"
)

Target "All" DoNothing

"SetupIronPython" ==> "All"

RunTargetOrDefault "All"
