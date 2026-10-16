param([string]$CommandProxy='')
. (Join-Path $PSScriptRoot 'kind-common.ps1') -CommandProxy $CommandProxy
Push-Location -LiteralPath $script:ThemisRepository
try {
    $version=Invoke-ThemisTool $script:ThemisKind @('version')
    if($version -notmatch '^kind v0\.32\.0 '){throw 'Install pinned Kind v0.32.0 into .cache/tools first'}
    $clusters=@(Invoke-ThemisTool $script:ThemisKind @('get','clusters'))
    if('themis-t20' -in $clusters -or (Test-Path -LiteralPath $script:ThemisState)){throw 'Setup requires a new cluster and state directory; existing state is never adopted or overwritten'}
    New-Item -ItemType Directory -Path $script:ThemisState | Out-Null
    if($env:OS -eq 'Windows_NT'){
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $script:ThemisState -AclObject $acl
    } else {
        Invoke-ThemisTool 'chmod' @('700',$script:ThemisState)
    }
    $owner=[ordered]@{version=1;clusterName='themis-t20';context='kind-themis-t20';stage='creating';previousClusters=$clusters}
    $encoding=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $script:ThemisState 'ownership.json'),($owner|ConvertTo-Json),$encoding)
    Invoke-ThemisTool $script:ThemisKind @('create','cluster','--name','themis-t20','--config','examples/kubernetes/kind.yaml','--kubeconfig',$script:ThemisConfig,'--wait','120s')
    $owner.clusterUID=Invoke-ThemisKubectl @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')
    $owner.stage='created'
    [IO.File]::WriteAllText((Join-Path $script:ThemisState 'ownership.json'),($owner|ConvertTo-Json),$encoding)
    & (Join-Path $PSScriptRoot 'kind-install.ps1') -CommandProxy $CommandProxy
} finally {Pop-Location}
