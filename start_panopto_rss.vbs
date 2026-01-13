Option Explicit

Dim fso, sh, dir, scriptPath, cfgPath, pyPath, pywPath, port
Dim cfg, re, m, ps, rc, url, healthUrl, refreshUrl

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

' Project directory = folder containing this VBS
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir

scriptPath = fso.BuildPath(dir, "PanoptoRSS.py")
cfgPath    = fso.BuildPath(dir, "config.json")

' Read port from config.json (default 8080)
port = 8080
If fso.FileExists(cfgPath) Then
  cfg = ""
  With fso.OpenTextFile(cfgPath, 1, False)
    cfg = .ReadAll
    .Close
  End With

  Set re = New RegExp
  re.Pattern = """port""\s*:\s*(\d+)"
  re.IgnoreCase = True
  re.Global = False

  If re.Test(cfg) Then
    Set m = re.Execute(cfg)(0)
    port = CInt(m.SubMatches(0))
  End If
End If

' Pick interpreter: prefer pythonw.exe inside venv to avoid console window
pywPath = fso.BuildPath(dir, ".venv\Scripts\pythonw.exe")
pyPath  = fso.BuildPath(dir, ".venv\Scripts\python.exe")

If Not fso.FileExists(pywPath) Then
  pywPath = fso.BuildPath(dir, "venv\Scripts\pythonw.exe")
End If
If Not fso.FileExists(pyPath) Then
  pyPath = fso.BuildPath(dir, "venv\Scripts\python.exe")
End If

Dim interpreter
interpreter = ""

If fso.FileExists(pywPath) Then
  interpreter = pywPath
ElseIf fso.FileExists(pyPath) Then
  interpreter = pyPath
Else
  ' Last resort: rely on PATH
  interpreter = "python"
End If

url = "http://127.0.0.1:" & port & "/index.html"
healthUrl = "http://127.0.0.1:" & port & "/health"
refreshUrl = "http://127.0.0.1:" & port & "/refresh"

' If already running: force a refresh and open the index (do not start another instance)
If HttpGetStatus(healthUrl, 250) = 200 Then
  Call HttpGetStatus(refreshUrl, 300000)
  sh.Run "cmd /c start """" " & Chr(34) & url & Chr(34), 0, False
  WScript.Quit 0
End If

' Start server (do not wait)
sh.Run Chr(34) & interpreter & Chr(34) & " " & Chr(34) & scriptPath & Chr(34), 0, False

' Wait for server to become reachable (up to ~10s)
Dim i, st
st = 0
For i = 1 To 50
  WScript.Sleep 200
  st = HttpGetStatus(healthUrl, 250)
  If st = 200 Then Exit For
Next

' Force a refresh now (bypasses the 10/15 minute interval)
Call HttpGetStatus(refreshUrl, 300000)

' Open index
sh.Run "cmd /c start """" " & Chr(34) & url & Chr(34), 0, False

' Optional: open index after launching
' sh.Run "cmd /c start " & Chr(34) & Chr(34) & " " & Chr(34) & url & Chr(34), 0, False

Function HttpGetStatus(u, receiveTimeoutMs)
  On Error Resume Next
  Dim req
  Set req = CreateObject("WinHttp.WinHttpRequest.5.1")
  req.SetTimeouts 2000, 2000, 2000, receiveTimeoutMs
  req.Open "GET", u, False
  req.Send
  If Err.Number <> 0 Then
    HttpGetStatus = 0
  Else
    HttpGetStatus = req.Status
  End If
  On Error GoTo 0
End Function
