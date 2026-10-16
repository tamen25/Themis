param([string]$CommandProxy='')
. (Join-Path $PSScriptRoot 'kind-common.ps1') -CommandProxy $CommandProxy
$owner=Assert-ThemisCluster
$actualNamespace=Invoke-ThemisKubectl @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}')
if($owner.namespaceUID -ne $actualNamespace){throw 'Namespace identity differs from owned setup; no controller update permitted'}
Push-Location -LiteralPath $script:ThemisRepository
try {
    $build=Join-Path $script:ThemisRepository '.cache/controller-image'
    New-Item -ItemType Directory -Force -Path $build | Out-Null
    $oldGOOS=$env:GOOS;$oldGOARCH=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
    try {
        $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
        Invoke-ThemisTool 'go' @('build','-trimpath','-o',(Join-Path $build 'themis-controller'),'./cmd/themis-controller')
    } finally {$env:GOOS=$oldGOOS;$env:GOARCH=$oldGOARCH;$env:CGO_ENABLED=$oldCGO}
    $hash=(Get-FileHash -LiteralPath (Join-Path $build 'themis-controller') -Algorithm SHA256).Hash.ToLowerInvariant()
    $image='themis-controller:t20-'+$hash
    Copy-Item -LiteralPath build/controller.Dockerfile -Destination (Join-Path $build 'Dockerfile') -Force
    Invoke-ThemisTool 'docker' @('build','-t',$image,$build)
    Invoke-ThemisTool $script:ThemisKind @('load','docker-image','--name','themis-t20',$image)
    $deployment=[IO.File]::ReadAllText((Join-Path $script:ThemisRepository 'config/kubernetes/controller.yaml')).Replace('themis-controller:t2.0',$image)
    $manifestPath=Join-Path $script:ThemisState 'controller.yaml'
    [IO.File]::WriteAllText($manifestPath,$deployment,[Text.UTF8Encoding]::new($false))
    Invoke-ThemisKubectl @('apply','-f',$manifestPath)
    Invoke-ThemisKubectl @('rollout','status','deployment/themis-controller','-n','themis-test','--timeout=120s')
    Write-Output "Owned controller image: $image"
} finally {Pop-Location}
