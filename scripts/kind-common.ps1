param([string]$CommandProxy='')
$ErrorActionPreference='Stop'
$script:ThemisRepository=Split-Path -Parent $PSScriptRoot
$script:ThemisState=Join-Path $script:ThemisRepository '.themis/kind-t20'
$script:ThemisConfig=Join-Path $script:ThemisState 'kubeconfig'
$script:ThemisKind=Join-Path $script:ThemisRepository '.cache/tools/kind.exe'
if($env:OS -ne 'Windows_NT'){$script:ThemisKind=Join-Path $script:ThemisRepository '.cache/tools/kind'}

function Invoke-ThemisTool([string]$Program,[string[]]$Arguments){
    $preference=$ErrorActionPreference
    $ErrorActionPreference='Continue'
    try {
        if($CommandProxy){$output=& $CommandProxy proxy $Program @Arguments}else{$output=& $Program @Arguments}
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$preference}
    if($code -ne 0){throw "$Program exited $code"}
    return $output
}
function Invoke-ThemisKubectl([string[]]$Arguments){
    Invoke-ThemisTool 'kubectl' (@('--kubeconfig',$script:ThemisConfig,'--context','kind-themis-t20')+$Arguments)
}
function Assert-ThemisCluster {
    $ownerPath=Join-Path $script:ThemisState 'ownership.json'
    if(-not(Test-Path -LiteralPath $ownerPath)){throw 'Owned cluster record missing; refusing adoption or teardown'}
    $owner=Get-Content -LiteralPath $ownerPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($owner.clusterName -ne 'themis-t20' -or $owner.context -ne 'kind-themis-t20' -or -not $owner.clusterUID){throw 'Complete owned cluster identity required'}
    $uid=Invoke-ThemisKubectl @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')
    if($uid -ne $owner.clusterUID){throw 'Cluster identity differs from owned setup; no mutation permitted'}
    return $owner
}
