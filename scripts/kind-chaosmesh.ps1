param(
    [ValidateSet('up','test','down')][string]$Action='up',
    [string]$State='.themis/chaosmesh-t24',
    [string]$CommandProxy=''
)
$ErrorActionPreference='Stop'
$repository=Split-Path -Parent $PSScriptRoot
$statePath=[IO.Path]::GetFullPath((Join-Path $repository $State))
$privateRoot=[IO.Path]::GetFullPath((Join-Path $repository '.themis'))
if(-not $statePath.StartsWith($privateRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'State must be within this repository private .themis directory'}
$admin=Join-Path $statePath 'admin-kubeconfig'
$kind=Join-Path $repository '.cache/tools/kind'
$binary=Join-Path $repository '.cache/themis-chaosmesh'
if($env:OS -eq 'Windows_NT'){$kind+='.exe';$binary+='.exe'}
$encoding=[Text.UTF8Encoding]::new($false)

function Tool([string]$Program,[string[]]$Arguments){
    $preference=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{if($CommandProxy){$output=& $CommandProxy proxy $Program @Arguments}else{$output=& $Program @Arguments};$code=$LASTEXITCODE}finally{$ErrorActionPreference=$preference}
    if($code -ne 0){if($Program -eq 'go' -and $Arguments[0] -eq 'test'){foreach($line in $output){[Console]::Out.WriteLine($line)}};throw "$Program exited $code"}
    return $output
}
function Protect([string]$Path,[bool]$Directory){
    if($env:OS -eq 'Windows_NT'){
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
        if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'}
        $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'));Set-Acl -LiteralPath $Path -AclObject $acl
    }else{if($Directory){$mode='700'}else{$mode='600'};Tool 'chmod' @($mode,$Path)}
}
function Private([string]$Name,[string]$Content){$path=Join-Path $statePath $Name;if(Test-Path -LiteralPath $path){throw 'Private state is never replaced'};[IO.File]::WriteAllText($path,$Content,$encoding);Protect $path $false;return $path}
function SaveOwner($Owner){$path=Join-Path $statePath 'bootstrap-owner.json';$exists=Test-Path -LiteralPath $path;[IO.File]::WriteAllText($path,($Owner|ConvertTo-Json -Depth 5),$encoding);if(-not $exists){Protect $path $false}}
function Kube([string[]]$Arguments){Tool 'kubectl' (@('--kubeconfig',$admin,'--context',$script:owner.context)+$Arguments)}
function Owned{
    if($script:owner.version -ne 'themis.chaosmesh-bootstrap/v1alpha1' -or $script:owner.clusterName -notmatch '^themis-t24-[a-f0-9]{12}$' -or $script:owner.context -ne ('kind-'+$script:owner.clusterName) -or -not $script:owner.clusterUID){throw 'Complete unique bootstrap identity required'}
    if((Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')) -ne $script:owner.clusterUID){throw 'Owned cluster UID mismatch; refusing mutation'}
    if($script:owner.namespaceUID -and (Kube @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}')) -ne $script:owner.namespaceUID){throw 'Owned namespace UID mismatch; refusing mutation'}
}
function Mutate([string[]]$Arguments){Owned;Kube $Arguments}

Push-Location -LiteralPath $repository
try{
    $env:GOCACHE=Join-Path $repository '.cache/go-build';$env:GOMODCACHE=Join-Path $repository '.cache/go-mod';$env:GOPATH=Join-Path $repository '.cache/go-path';$env:GOTMPDIR=Join-Path $repository '.cache/tmp'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE,$env:GOMODCACHE,$env:GOPATH,$env:GOTMPDIR|Out-Null
    if($Action -ne 'up'){
        $script:owner=Get-Content -LiteralPath (Join-Path $statePath 'bootstrap-owner.json') -Raw|ConvertFrom-Json
        Owned
        if($Action -eq 'down'){
            Tool $kind @('delete','cluster','--name',$script:owner.clusterName)
            Write-Output 'Deleted only the unique UID-verified T2.4 cluster; private records retained.'
        }else{
            Tool 'go' @('build','-trimpath','-o',$binary,'./cmd/themis-chaosmesh')
            $env:THEMIS_KIND_CHAOSMESH_PLANNING='1';$env:THEMIS_CHAOSMESH_STATE=$statePath;$env:THEMIS_CHAOSMESH_BINARY=$binary;$env:THEMIS_TEST_COMMAND_PROXY=$CommandProxy
            Tool 'go' @('test','-count=1','-v','./test/chaosmesh')
        }
        return
    }
    if(Test-Path -LiteralPath $statePath){throw 'Fresh private state required; never adopts existing state or clusters'}
    if((Tool $kind @('version')) -notmatch '^kind v0\.32\.0 '){throw 'Pinned Kind 0.32.0 required'}
    $previous=@(Tool $kind @('get','clusters'))
    $name='themis-t24-'+[guid]::NewGuid().ToString('N').Substring(0,12)
    if($previous -contains $name){throw 'Refusing to adopt existing cluster'}
    New-Item -ItemType Directory -Path $statePath|Out-Null;Protect $statePath $true
    $script:owner=[ordered]@{version='themis.chaosmesh-bootstrap/v1alpha1';clusterName=$name;context=('kind-'+$name);clusterUID='';namespaceUID='';previousClusters=$previous}
    SaveOwner $script:owner
    Tool $kind @('create','cluster','--name',$name,'--config','examples/kubernetes-experiment/kind.yaml','--kubeconfig',$admin,'--wait','120s')
    Protect $admin $false
    $script:owner.clusterUID=Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}');SaveOwner $script:owner
    Mutate @('create','-f','examples/kubernetes/workload.yaml')
    $script:owner.namespaceUID=Kube @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}');SaveOwner $script:owner
    Mutate @('apply','-f','config/crd/verificationruns.yaml')
    Kube @('wait','--for=condition=Established','crd/verificationruns.verification.themis.dev','--timeout=60s')
    Mutate @('apply','-f','config/kubernetes/admission.yaml')
    Mutate @('apply','-f','config/kubernetes/rbac.yaml')
    $lock=Get-Content -LiteralPath internal/chaosmesh/upstream.lock.json -Raw|ConvertFrom-Json
    if($lock.version -ne 'themis.chaosmesh-upstream-lock/v1alpha1' -or $lock.faultExecutionEnabled -or $lock.installation -ne 'CRD_SCHEMA_ONLY_NO_PROVIDER_WORKLOADS'){throw 'Planning-only upstream lock required'}
    $crdPath=Join-Path $statePath 'networkchaos-crd.yaml'
    Invoke-WebRequest -UseBasicParsing -Uri $lock.crdURL -OutFile $crdPath;Protect $crdPath $false
    if((Get-FileHash -LiteralPath $crdPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $lock.auditedArtifacts.networkChaosCRDSHA256){throw 'Upstream CRD digest mismatch'}
    Mutate @('apply','-f',$crdPath)
    Kube @('wait','--for=condition=Established','crd/networkchaos.chaos-mesh.org','--timeout=60s')
    Mutate @('apply','-f','config/kubernetes/quota.yaml')
    Kube @('wait','--for=jsonpath={.status.hard.pods}=8','resourcequota/themis-test-budget','-n','themis-test','--timeout=60s')
    # Built-in Pod quota readiness does not imply CRD discovery/count readiness.
    $quotaReady=$false
    for($quotaStart=[DateTime]::UtcNow;([DateTime]::UtcNow-$quotaStart).TotalSeconds -lt 90;){
        $quota=(Kube @('get','resourcequota','themis-test-budget','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
        if($quota.status.hard.'count/verificationruns.verification.themis.dev' -eq '32' -and $null -ne $quota.status.used.'count/verificationruns.verification.themis.dev'){$quotaReady=$true;break}
        Start-Sleep -Milliseconds 300
    }
    if(-not $quotaReady){throw 'VerificationRun quota discovery not ready; no request permitted'}
    $pins=Private 'pins.yaml' ("apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: themis-controller-pins`n  namespace: themis-test`ndata:`n  clusterUID: '$($script:owner.clusterUID)'`n  namespaceUID: '$($script:owner.namespaceUID)'`n")
    Mutate @('apply','-f',$pins)
    $build=Join-Path $repository '.cache/chaosmesh-controller-image';New-Item -ItemType Directory -Force -Path $build|Out-Null
    $oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
    try{$env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0';Tool 'go' @('build','-trimpath','-o',(Join-Path $build 'themis-controller'),'./cmd/themis-controller')}finally{$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO}
    $image='themis-controller:t24-'+(Get-FileHash -LiteralPath (Join-Path $build 'themis-controller') -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath build/controller.Dockerfile -Destination (Join-Path $build 'Dockerfile')
    Owned;Tool 'docker' @('build','-t',$image,$build);Owned;Tool $kind @('load','docker-image','--name',$name,$image)
    $controller=Private 'controller.yaml' ([IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/controller.yaml')).Replace('themis-controller:t2.0',$image))
    Mutate @('apply','-f',$controller)
    Kube @('rollout','status','deployment/themis-controller','-n','themis-test','--timeout=120s')
    Kube @('rollout','status','deployment/synthetic','-n','themis-test','--timeout=120s')
    $dep=(Kube @('get','deployment','synthetic','-n','themis-test','-o','json'))-join "`n"|ConvertFrom-Json
    $pods=(Kube @('get','pods','-n','themis-test','-l','app=themis-synthetic','-o','json'))-join "`n"|ConvertFrom-Json
    if($pods.items.Count -ne 1){throw 'Exactly one synthetic Pod required'}
    $rs=$pods.items[0].metadata.ownerReferences[0].name
    $rbac=Private 'planner-rbac.yaml' ([IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/chaosmesh-planner-rbac.yaml')).Replace('REPLACE_WITH_REPLICA_SET_NAME',$rs))
    Mutate @('apply','-f',$rbac)
    Owned;$token=(Kube @('create','token','themis-chaosmesh-planner','-n','themis-test','--duration=1h'))-join ''
    $actorUID=Kube @('get','serviceaccount','themis-chaosmesh-planner','-n','themis-test','-o','jsonpath={.metadata.uid}')
    $base=(Kube @('config','view','--raw','--minify','-o','json'))-join "`n"|ConvertFrom-Json
    $planner=@{apiVersion='v1';kind='Config';clusters=$base.clusters;users=@(@{name='themis-chaosmesh-planner';user=@{token=$token}});contexts=@(@{name=$script:owner.context;context=@{cluster=$base.clusters[0].name;user='themis-chaosmesh-planner'}});'current-context'=$script:owner.context}
    $null=Private 'planner-kubeconfig' ($planner|ConvertTo-Json -Depth 12)
    $planning=@{version='themis.chaosmesh-owned-kind/v1alpha1';directory=$statePath;clusterName=$name;context=$script:owner.context;clusterUID=$script:owner.clusterUID;namespaceUID=$script:owner.namespaceUID;deploymentUID=$dep.metadata.uid;operator=@{name='system:serviceaccount:themis-test:themis-chaosmesh-planner';uid=$actorUID}}
    $null=Private 'planning-owner.json' ($planning|ConvertTo-Json -Depth 5)
    $request=Private 'run.yaml' ([IO.File]::ReadAllText((Join-Path $repository 'examples/chaosmesh/run.yaml')).Replace('REPLACE_WITH_ACTUAL_DEPLOYMENT_UID',$dep.metadata.uid))
    Mutate @('create','-f',$request)
    Kube @('wait','--for=condition=PlanReady','verificationrun/external-latency-request','-n','themis-test','--timeout=60s')
    Tool 'go' @('build','-trimpath','-o',$binary,'./cmd/themis-chaosmesh')
    Write-Output "Owned $name planning environment ready. Only the pinned NetworkChaos CRD schema is installed. No Chaos Mesh controller, daemon, provider runtime privileges or fault resource exists."
}finally{Pop-Location}
